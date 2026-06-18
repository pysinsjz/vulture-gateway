package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeUpstream 受控上游：AuthorizeURL 把 linkedState 放进 query 便于测试提取；Exchange 派生 subject。
type fakeUpstream struct {
	exchangeErr error
	subject     string
}

func (f *fakeUpstream) AuthorizeURL(linkedState string) string {
	return "https://idp.example/authorize?state=" + url.QueryEscape(linkedState)
}

func (f *fakeUpstream) Exchange(_ context.Context, code string) (string, error) {
	if f.exchangeErr != nil {
		return "", f.exchangeErr
	}
	if f.subject != "" {
		return f.subject, nil
	}
	return "subject-" + code, nil
}

// fakeUserRepo 内存 User 仓，记录 resolve/create 的 subject。
type fakeUserRepo struct {
	bySubject map[string]*model.User
	seq       int64
}

func newFakeUserRepo() *fakeUserRepo { return &fakeUserRepo{bySubject: map[string]*model.User{}} }

func (r *fakeUserRepo) ResolveOrCreateBySubject(_ context.Context, subject string) (*model.User, error) {
	if u, ok := r.bySubject[subject]; ok {
		return u, nil
	}
	r.seq++
	u := &model.User{ID: r.seq, UUID: "usr_" + subject, Subject: subject}
	r.bySubject[subject] = u
	return u, nil
}

// fakeTransactor 直接执行回调，不启真实事务（测试用）。
type fakeTransactor struct{}

func (fakeTransactor) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// fakeDeviceRepo 内存 Device 仓。
type fakeDeviceRepo struct{ created []*model.Device }

func (r *fakeDeviceRepo) Create(_ context.Context, d *model.Device) error {
	r.created = append(r.created, d)
	return nil
}

// fakeRefreshRepo 内存 refresh token 仓（按哈希索引 + 创建序列，线程安全）。
type fakeRefreshRepo struct {
	mu           sync.Mutex
	byHash       map[string]*model.RefreshToken
	created      []*model.RefreshToken
	failMarkUsed bool // 置 true 时 MarkUsedIfUnused 恒返回 false，模拟并发竞态败者
}

func newFakeRefreshRepo() *fakeRefreshRepo {
	return &fakeRefreshRepo{byHash: map[string]*model.RefreshToken{}}
}

func (r *fakeRefreshRepo) Create(_ context.Context, rt *model.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *rt
	r.byHash[rt.TokenHash] = &cp
	r.created = append(r.created, &cp)
	return nil
}

func (r *fakeRefreshRepo) FindByHash(_ context.Context, h string) (*model.RefreshToken, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.byHash[h]
	if !ok {
		return nil, false, nil
	}
	cp := *rt
	return &cp, true, nil
}

func (r *fakeRefreshRepo) MarkUsedIfUnused(_ context.Context, h string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failMarkUsed {
		return false, nil
	}
	rt, ok := r.byHash[h]
	if !ok || rt.Used {
		return false, nil
	}
	rt.Used = true
	return true, nil
}

func (r *fakeRefreshRepo) RevokeFamily(_ context.Context, fam string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.byHash {
		if rt.FamilyID == fam {
			rt.Revoked = true
		}
	}
	return nil
}

// inject 直接塞入一条 refresh 记录（测试构造过期/特定状态用）。
func (r *fakeRefreshRepo) inject(rt *model.RefreshToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *rt
	r.byHash[rt.TokenHash] = &cp
}

type oauthFixture struct {
	engine    *gin.Engine
	mr        *miniredis.Miniredis
	rdb       *redis.Client
	upstream  *fakeUpstream
	users     *fakeUserRepo
	gwcodes   *auth.GWCodeStore
	devices   *fakeDeviceRepo
	refreshes *fakeRefreshRepo
}

const (
	fixtureSecret      = "oauth-fixture-secret"
	fixtureGraceWindow = 60 * time.Second
)

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	up := &fakeUpstream{}
	users := newFakeUserRepo()
	devices := &fakeDeviceRepo{}
	refreshes := newFakeRefreshRepo()
	authzStore := auth.NewAuthzStore(rdb, 10*time.Minute)
	gwStore := auth.NewGWCodeStore(rdb, 60*time.Second)
	replayStore := auth.NewRefreshReplayStore(rdb, fixtureGraceWindow)
	locker := auth.NewLocker(rdb)

	signer := auth.NewSigner(config.JWTConfig{Secret: fixtureSecret, Issuer: "vulture-gateway", AccessTTL: 30 * time.Minute})
	tvs := auth.NewTokenVersionStore(rdb)
	svc := service.NewOAuthService(fakeTransactor{}, devices, refreshes, gwStore, tvs, replayStore, locker, signer, 1440*time.Hour, fixtureGraceWindow)

	h := handler.NewOAuthHandler(up, authzStore, gwStore, users, svc, "vulture-desktop")

	r := gin.New()
	r.GET("/oauth/authorize", h.Authorize)
	r.GET("/oauth/callback/casdoor", h.Callback)
	r.POST("/oauth/token", h.Token)
	// 受保护探针，用于验证换得的 access JWT 能跑通 JWTAuth（首次登录闭环）。
	probe := handler.NewProbeHandler()
	v1 := r.Group("/api/v1")
	v1.Use(middleware.JWTAuth(signer, tvs, nil))
	v1.GET("/whoami", probe.Whoami)

	return &oauthFixture{engine: r, mr: mr, rdb: rdb, upstream: up, users: users, gwcodes: gwStore, devices: devices, refreshes: refreshes}
}

func (f *oauthFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec
}

const validRedirect = "http://127.0.0.1:5173/callback"

func validAuthorizeURL() string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "vulture-desktop")
	q.Set("code_challenge", "challenge-abc")
	q.Set("code_challenge_method", "S256")
	q.Set("state", "orig-xyz")
	q.Set("redirect_uri", validRedirect)
	return "/oauth/authorize?" + q.Encode()
}

// /oauth/authorize 合法参数 → 302 跳上游，并暂存 state/challenge/redirect_uri（经回调成功间接验证）。
func TestAuthorize_ValidRedirectsToUpstream(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.get(t, validAuthorizeURL())

	if rec.Code != http.StatusFound {
		t.Fatalf("期望 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "idp.example" {
		t.Errorf("应跳上游 idp.example, 实际 %s", loc.Host)
	}
	if loc.Query().Get("state") == "" {
		t.Error("跳上游应携带关联 state")
	}
}

// 非法参数一律被拒（400）。
func TestAuthorize_RejectsInvalid(t *testing.T) {
	base := url.Values{
		"response_type":         {"code"},
		"client_id":             {"vulture-desktop"},
		"code_challenge":        {"challenge-abc"},
		"code_challenge_method": {"S256"},
		"state":                 {"orig-xyz"},
		"redirect_uri":          {validRedirect},
	}
	mutate := func(fn func(url.Values)) string {
		q := url.Values{}
		for k, v := range base {
			q[k] = append([]string{}, v...)
		}
		fn(q)
		return "/oauth/authorize?" + q.Encode()
	}

	cases := map[string]string{
		"response_type 非 code": mutate(func(q url.Values) { q.Set("response_type", "token") }),
		"client_id 错误":         mutate(func(q url.Values) { q.Set("client_id", "someone-else") }),
		"缺 code_challenge":     mutate(func(q url.Values) { q.Del("code_challenge") }),
		"method 非 S256":        mutate(func(q url.Values) { q.Set("code_challenge_method", "plain") }),
		"缺 state":              mutate(func(q url.Values) { q.Del("state") }),
		"redirect_uri 非回环":     mutate(func(q url.Values) { q.Set("redirect_uri", "https://evil.example/callback") }),
		"redirect_uri path 错":  mutate(func(q url.Values) { q.Set("redirect_uri", "http://127.0.0.1:5173/pwn") }),
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOAuthFixture(t)
			rec := f.get(t, target)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("期望 400, 实际 %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// redirect_uri 端口任意均应通过。
func TestAuthorize_AnyLoopbackPortAllowed(t *testing.T) {
	for _, ru := range []string{
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:65535/callback",
		"http://[::1]:5173/callback",
	} {
		t.Run(ru, func(t *testing.T) {
			f := newOAuthFixture(t)
			q := url.Values{}
			q.Set("response_type", "code")
			q.Set("client_id", "vulture-desktop")
			q.Set("code_challenge", "cc")
			q.Set("code_challenge_method", "S256")
			q.Set("state", "s")
			q.Set("redirect_uri", ru)
			rec := f.get(t, "/oauth/authorize?"+q.Encode())
			if rec.Code != http.StatusFound {
				t.Fatalf("回环端口任意应通过, %s 得 %d", ru, rec.Code)
			}
		})
	}
}

// 全链路：authorize → callback → 回跳带 GW_CODE + 原 state；GW_CODE 绑定 challenge + 创建 User。
func TestAuthorizeCallback_FullFlow(t *testing.T) {
	f := newOAuthFixture(t)

	authRec := f.get(t, validAuthorizeURL())
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize 期望 302, 实际 %d", authRec.Code)
	}
	upstreamLoc, _ := url.Parse(authRec.Header().Get("Location"))
	linkedState := upstreamLoc.Query().Get("state")

	cbRec := f.get(t, "/oauth/callback/casdoor?code=UPSTREAM_CODE&state="+url.QueryEscape(linkedState))
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback 期望 302, 实际 %d: %s", cbRec.Code, cbRec.Body.String())
	}

	backLoc, _ := url.Parse(cbRec.Header().Get("Location"))
	if backLoc.Scheme+"://"+backLoc.Host+backLoc.Path != validRedirect {
		t.Errorf("应回跳 %s, 实际 %s", validRedirect, backLoc.String())
	}
	if got := backLoc.Query().Get("state"); got != "orig-xyz" {
		t.Errorf("回跳 state 应为原值 orig-xyz, 实际 %q", got)
	}
	gwCode := backLoc.Query().Get("code")
	if gwCode == "" {
		t.Fatal("回跳缺 GW_CODE")
	}

	// GW_CODE 绑定 PKCE challenge + User。
	data, found, err := f.gwcodes.Consume(context.Background(), gwCode)
	if err != nil || !found {
		t.Fatalf("应能取用 GW_CODE, found=%v err=%v", found, err)
	}
	if data.CodeChallenge != "challenge-abc" {
		t.Errorf("GW_CODE 应绑定 challenge-abc, 实际 %q", data.CodeChallenge)
	}
	if data.UserUUID != "usr_subject-UPSTREAM_CODE" {
		t.Errorf("GW_CODE 应绑定 User, 实际 %q", data.UserUUID)
	}
	if _, ok := f.users.bySubject["subject-UPSTREAM_CODE"]; !ok {
		t.Error("应已解析/创建 User")
	}
}

// callback 用未知/已过期 state → 400（无 redirect_uri 可回跳）。
func TestCallback_UnknownState(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.get(t, "/oauth/callback/casdoor?code=c&state=st_unknown")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知 state 期望 400, 实际 %d", rec.Code)
	}
}

// callback 上游换码失败 → 回跳 redirect_uri 带 error=server_error + 原 state。
func TestCallback_UpstreamExchangeFailureRedirects(t *testing.T) {
	f := newOAuthFixture(t)
	f.upstream.exchangeErr = context.DeadlineExceeded

	authRec := f.get(t, validAuthorizeURL())
	upstreamLoc, _ := url.Parse(authRec.Header().Get("Location"))
	linkedState := upstreamLoc.Query().Get("state")

	rec := f.get(t, "/oauth/callback/casdoor?code=c&state="+url.QueryEscape(linkedState))
	if rec.Code != http.StatusFound {
		t.Fatalf("换码失败应回跳 302, 实际 %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "server_error" {
		t.Errorf("应回跳 error=server_error, 实际 %q", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "orig-xyz" {
		t.Errorf("回跳应带原 state, 实际 %q", loc.Query().Get("state"))
	}
}
