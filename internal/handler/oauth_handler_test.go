package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
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

// fakeDeviceRepo 内存 Device 仓（按 uuid 索引，线程安全）。
type fakeDeviceRepo struct {
	mu                sync.Mutex
	byUUID            map[string]*model.Device
	created           []*model.Device
	lastActiveUpdates int
}

func newFakeDeviceRepo() *fakeDeviceRepo {
	return &fakeDeviceRepo{byUUID: map[string]*model.Device{}}
}

func (r *fakeDeviceRepo) Create(_ context.Context, d *model.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *d
	if cp.CreatedAt == 0 {
		cp.CreatedAt = cp.LastActiveAt
	}
	r.byUUID[d.UUID] = &cp
	r.created = append(r.created, &cp)
	return nil
}

func (r *fakeDeviceRepo) ListByUser(_ context.Context, userUUID string) ([]model.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.Device
	for _, d := range r.byUUID {
		if d.UserUUID == userUUID {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (r *fakeDeviceRepo) GetByUUID(_ context.Context, uuid string) (*model.Device, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.byUUID[uuid]
	if !ok {
		return nil, false, nil
	}
	cp := *d
	return &cp, true, nil
}

func (r *fakeDeviceRepo) UpdateLastActive(_ context.Context, uuid string, ts int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.byUUID[uuid]; ok {
		d.LastActiveAt = ts
	}
	r.lastActiveUpdates++
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

func (r *fakeRefreshRepo) RevokeByDevice(_ context.Context, dev string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.byHash {
		if rt.DeviceUUID == dev {
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

	users := newFakeUserRepo()
	devices := newFakeDeviceRepo()
	refreshes := newFakeRefreshRepo()
	authzStore := auth.NewAuthzStore(rdb, 10*time.Minute)
	gwStore := auth.NewGWCodeStore(rdb, 60*time.Second)
	replayStore := auth.NewRefreshReplayStore(rdb, fixtureGraceWindow)
	locker := auth.NewLocker(rdb)

	signer := auth.NewSigner(config.JWTConfig{Secret: fixtureSecret, Issuer: "vulture-gateway", AccessTTL: 30 * time.Minute})
	tvs := auth.NewTokenVersionStore(rdb)
	svc := service.NewOAuthService(fakeTransactor{}, devices, refreshes, gwStore, tvs, replayStore, locker, signer, 1440*time.Hour, fixtureGraceWindow)
	deviceSvc := service.NewDeviceService(tvs, devices, refreshes)

	h := handler.NewOAuthHandler(authzStore, gwStore, users, svc, "vulture-desktop")
	dh := handler.NewDeviceHandler(signer, deviceSvc)

	r := gin.New()
	r.GET("/oauth/authorize", h.Authorize)
	r.POST("/oauth/token", h.Token)
	// 管理 API 组：whoami（探针）+ A3 logout/devices。logout 走公开例外（自带鉴权）。
	probe := handler.NewProbeHandler()
	v1 := r.Group("/api/v1")
	v1.Use(middleware.JWTAuth(signer, tvs, middleware.DefaultPublicPaths))
	v1.GET("/whoami", probe.Whoami)
	v1.POST("/auth/logout", dh.Logout)
	v1.GET("/devices", dh.ListDevices)
	v1.DELETE("/devices/:device_id", dh.DeleteDevice)
	// LLM 代理族占位（JWTAuthLLM）：用于校验三族错误体分流（#15）；真实端点见 LLM 域 #23+。
	llm := r.Group("/v1")
	llm.Use(middleware.JWTAuthLLM(signer, tvs, nil))
	llm.GET("/ping", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	return &oauthFixture{engine: r, mr: mr, rdb: rdb, users: users, gwcodes: gwStore, devices: devices, refreshes: refreshes}
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

// /oauth/authorize 合法参数 → 302 跳网关登录页 /oauth/login，并携带 linkedState（lk），
// 同时暂存 state/challenge/redirect_uri（经登录提交链路间接验证，阶段五）。
func TestAuthorize_RedirectsToLoginPage(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.get(t, validAuthorizeURL())

	if rec.Code != http.StatusFound {
		t.Fatalf("期望 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/oauth/login" {
		t.Errorf("应跳网关登录页 /oauth/login, 实际 %s", loc.Path)
	}
	if loc.Query().Get("lk") == "" {
		t.Error("跳登录页应携带 linkedState（lk）")
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

// 注：authorize→callback→token 全链路、callback 失败回跳分支等用例随 Casdoor 上游删除而下线，
// 自建登录页（GET/POST /oauth/login）的全链路用例由阶段五 LoginHandler 测试承接（ADR-0013）。
