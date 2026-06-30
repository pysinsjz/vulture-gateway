package handler_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/auth/signin"
	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/notify"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeIdentityRepo 内存身份仓（登录页测试用）。
// noopVKeyProvisioner 是 ADR-0014 eager 签发的测试假实现：登录流程不依赖真实 litellm。
type noopVKeyProvisioner struct{}

func (noopVKeyProvisioner) GetOrCreateVirtualKey(_ context.Context, _ string) (string, error) {
	return "sk-test", nil
}

type fakeIdentityRepo struct {
	byKey map[string]*model.Identity
}

func newFakeIdentityRepo() *fakeIdentityRepo {
	return &fakeIdentityRepo{byKey: map[string]*model.Identity{}}
}

func (r *fakeIdentityRepo) FindByTypeIdentifier(_ context.Context, typ, identifier string) (*model.Identity, bool, error) {
	if id, ok := r.byKey[typ+"|"+identifier]; ok {
		cp := *id
		return &cp, true, nil
	}
	return nil, false, nil
}

func (r *fakeIdentityRepo) FindByUserUUIDAndType(_ context.Context, userUUID, typ string) (*model.Identity, bool, error) {
	for _, id := range r.byKey {
		if id.UserUUID == userUUID && id.Type == typ {
			cp := *id
			return &cp, true, nil
		}
	}
	return nil, false, nil
}

func (r *fakeIdentityRepo) ListLocalByUserUUID(_ context.Context, userUUID string) ([]model.Identity, error) {
	var out []model.Identity
	for _, id := range r.byKey {
		if id.UserUUID == userUUID && id.Provider == "" {
			out = append(out, *id)
		}
	}
	return out, nil
}

func (r *fakeIdentityRepo) UpdateSecretByUserUUID(_ context.Context, userUUID, secretHash string) (int64, error) {
	var rows int64
	for _, id := range r.byKey {
		if id.UserUUID == userUUID && id.Provider == "" {
			id.Secret = secretHash
			rows++
		}
	}
	return rows, nil
}

func (r *fakeIdentityRepo) Create(_ context.Context, id *model.Identity) error {
	r.byKey[id.Type+"|"+id.Identifier] = id
	return nil
}

type loginFixture struct {
	engine     *gin.Engine
	authz      *auth.AuthzStore
	csrf       *auth.CSRFStore
	otp        *auth.OTPStore
	identities *fakeIdentityRepo
	hasher     auth.PasswordHasher
	pub        *rsa.PublicKey
}

// newLoginFixture 装配默认 allowPlaintext=false 的登录 fixture（兼容既有调用）。
// 需要旁路开启的测试用 newLoginFixtureWithBypass。
func newLoginFixture(t *testing.T) *loginFixture {
	return newLoginFixtureAllowingPlaintext(t, false)
}

// newLoginFixtureAllowingPlaintext 显式控制 AllowPlaintextPassword，用于旁路回归测试。
func newLoginFixtureAllowingPlaintext(t *testing.T, allowPlaintext bool) *loginFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	rsaDec, _ := auth.NewRSADecryptor(privPEM)

	authzStore := auth.NewAuthzStore(rdb, 10*time.Minute)
	gwStore := auth.NewGWCodeStore(rdb, 60*time.Second)
	csrfStore := auth.NewCSRFStore(rdb, 10*time.Minute)
	otpStore := auth.NewOTPStore(rdb, 5*time.Minute, 60*time.Second, 5, "")
	limiter := auth.NewRateLimiter(rdb, auth.RateLimitConfig{LoginMaxFailures: 5, LoginLockWindow: 15 * time.Minute, SendMax: 3, SendWindow: 10 * time.Minute})

	identities := newFakeIdentityRepo()
	users := newFakeUserRepo()
	hasher := auth.NewBcryptHasher(4)
	emailCode := signin.NewEmailCodeMethod(otpStore, identities, users, fakeTransactor{})
	smsCode := signin.NewSmsCodeMethod(otpStore, identities, users, fakeTransactor{})
	password := signin.NewPasswordMethod(identities, hasher, rsaDec, limiter)
	registry := signin.NewRegistry(password, emailCode, smsCode)

	otpSvc := service.NewOTPService(otpStore, limiter, map[string]notify.CodeSender{
		model.ProviderCategoryEmail: notify.NewStubSender("email"),
	})

	h := handler.NewLoginHandler(registry, otpSvc, authzStore, gwStore, users, noopVKeyProvisioner{}, rsaDec, csrfStore, allowPlaintext)

	r := gin.New()
	r.GET("/oauth/login", h.LoginPage)
	r.POST("/oauth/login", h.Login)
	r.POST("/oauth/send-code", h.SendCode)

	return &loginFixture{
		engine: r, authz: authzStore, csrf: csrfStore, otp: otpStore,
		identities: identities, hasher: hasher, pub: &key.PublicKey,
	}
}

// seedPasswordIdentity 预置一条已设密码的 email 身份，并返回。
func (f *loginFixture) seedPasswordIdentity(t *testing.T, email, userUUID, password string) {
	t.Helper()
	hash, err := f.hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash 失败: %v", err)
	}
	f.identities.byKey[model.IdentityTypeEmail+"|"+email] = &model.Identity{
		UUID: "idn_seed", UserUUID: userUUID, Type: model.IdentityTypeEmail, Identifier: email, Secret: hash,
	}
}

// encryptPassword 用 fixture 公钥做 RSA-OAEP(SHA-256) 加密并 base64（模拟前端提交）。
func (f *loginFixture) encryptPassword(t *testing.T, plain string) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, f.pub, []byte(plain), nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func (f *loginFixture) seedAuthz(t *testing.T, lk, redirectURI, origState string) {
	t.Helper()
	err := f.authz.Save(context.Background(), lk, auth.AuthzRequest{
		OrigState: origState, CodeChallenge: "challenge-abc", RedirectURI: redirectURI,
	})
	if err != nil {
		t.Fatalf("seed authz 失败: %v", err)
	}
}

func (f *loginFixture) do(t *testing.T, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec
}

func TestLoginPage_RendersForm(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")

	rec := f.do(t, http.MethodGet, "/oauth/login?lk=lk1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`name="lk"`, `name="csrf"`, `id="pubkey"`, `value="password"`, `value="email_code"`} {
		if !strings.Contains(body, want) {
			t.Errorf("登录页应含 %q", want)
		}
	}
}

func TestLoginPage_InvalidLinkedState(t *testing.T) {
	f := newLoginFixture(t)
	rec := f.do(t, http.MethodGet, "/oauth/login?lk=nope", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无效 lk 期望 400, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "登录失败") {
		t.Error("应渲染错误页")
	}
}

func TestLogin_EmailCode_FullFlow(t *testing.T) {
	f := newLoginFixture(t)
	const redirectURI = "http://127.0.0.1:5173/callback"
	f.seedAuthz(t, "lk1", redirectURI, "orig-xyz")

	ctx := context.Background()
	token, _ := f.csrf.Issue(ctx, "lk1")
	code, _ := f.otp.Issue(ctx, "u@x.com")

	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":         {"lk1"},
		"csrf":       {token},
		"method":     {"email_code"},
		"identifier": {"u@x.com"},
		"credential": {code},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("登录成功应 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != redirectURI {
		t.Errorf("应回跳 %s, 实际 %s", redirectURI, loc.String())
	}
	if loc.Query().Get("code") == "" {
		t.Error("回跳应带 GW_CODE")
	}
	if loc.Query().Get("state") != "orig-xyz" {
		t.Errorf("回跳应带原 state, 实际 %q", loc.Query().Get("state"))
	}
}

func TestLogin_BadCSRF_ReRenders(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	code, _ := f.otp.Issue(context.Background(), "u@x.com")

	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":         {"lk1"},
		"csrf":       {"wrong-token"},
		"method":     {"email_code"},
		"identifier": {"u@x.com"},
		"credential": {code},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("CSRF 失败应重渲染 200, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "会话已失效") {
		t.Error("应提示会话失效")
	}
}

func TestLogin_WrongCode_ReRenders(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	ctx := context.Background()
	token, _ := f.csrf.Issue(ctx, "lk1")
	_, _ = f.otp.Issue(ctx, "u@x.com")

	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":         {"lk1"},
		"csrf":       {token},
		"method":     {"email_code"},
		"identifier": {"u@x.com"},
		"credential": {"000000"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("验证码错误应重渲染 200, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "验证码错误") {
		t.Error("应提示验证码错误")
	}
}

func TestLogin_Password_FullFlow(t *testing.T) {
	f := newLoginFixture(t)
	const redirectURI = "http://127.0.0.1:5173/callback"
	f.seedAuthz(t, "lk1", redirectURI, "orig-pw")
	f.seedPasswordIdentity(t, "u@x.com", "usr_pw", "correct-pass")

	token, _ := f.csrf.Issue(context.Background(), "lk1")
	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":         {"lk1"},
		"csrf":       {token},
		"method":     {"password"},
		"identifier": {"u@x.com"},
		"credential": {f.encryptPassword(t, "correct-pass")},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("密码登录成功应 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" || loc.Query().Get("state") != "orig-pw" {
		t.Errorf("应回跳带 GW_CODE+原 state, 实际 %s", loc.String())
	}
}

func TestLogin_WrongPassword_ReRenders(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	f.seedPasswordIdentity(t, "u@x.com", "usr_pw", "correct-pass")

	token, _ := f.csrf.Issue(context.Background(), "lk1")
	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":         {"lk1"},
		"csrf":       {token},
		"method":     {"password"},
		"identifier": {"u@x.com"},
		"credential": {f.encryptPassword(t, "wrong-pass")},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("密码错误应重渲染 200, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "标识或密码错误") {
		t.Error("应提示标识或密码错误")
	}
}

func TestLogin_AccountLockedAfterFailures(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	f.seedPasswordIdentity(t, "u@x.com", "usr_pw", "correct-pass")
	wrong := f.encryptPassword(t, "wrong-pass")

	post := func() *httptest.ResponseRecorder {
		token, _ := f.csrf.Issue(context.Background(), "lk1")
		return f.do(t, http.MethodPost, "/oauth/login", url.Values{
			"lk": {"lk1"}, "csrf": {token}, "method": {"password"}, "identifier": {"u@x.com"}, "credential": {wrong},
		})
	}
	// 前 4 次：标识或密码错误。
	for i := 0; i < 4; i++ {
		if rec := post(); !strings.Contains(rec.Body.String(), "标识或密码错误") {
			t.Fatalf("第 %d 次应提示密码错, body=%s", i+1, rec.Body.String())
		}
	}
	// 第 5 次触发锁定提示。
	if rec := post(); !strings.Contains(rec.Body.String(), "尝试过于频繁") {
		t.Errorf("第 5 次应提示锁定, body=%s", rec.Body.String())
	}
}

func TestLoginPage_RendersSmsMethod(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	rec := f.do(t, http.MethodGet, "/oauth/login?lk=lk1", nil)
	if !strings.Contains(rec.Body.String(), `value="sms_code"`) || !strings.Contains(rec.Body.String(), "手机验证码") {
		t.Error("登录页应含手机验证码方式")
	}
}

func TestSendCode_ResendTooSoon(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")

	form := url.Values{"lk": {"lk1"}, "method": {"email_code"}, "identifier": {"u@x.com"}}
	if rec := f.do(t, http.MethodPost, "/oauth/send-code", form); rec.Code != http.StatusOK {
		t.Fatalf("首发应 200, 实际 %d", rec.Code)
	}
	rec := f.do(t, http.MethodPost, "/oauth/send-code", form)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("60s 内重发应 429, 实际 %d", rec.Code)
	}
}

func TestSendCode_Email(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")

	rec := f.do(t, http.MethodPost, "/oauth/send-code", url.Values{
		"lk":         {"lk1"},
		"method":     {"email_code"},
		"identifier": {"u@x.com"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("发码应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("应返回 ok:true, body=%s", rec.Body.String())
	}
}

func TestSendCode_UnsupportedMethod(t *testing.T) {
	f := newLoginFixture(t)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")

	rec := f.do(t, http.MethodPost, "/oauth/send-code", url.Values{
		"lk":         {"lk1"},
		"method":     {"password"},
		"identifier": {"u@x.com"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("password 不支持发码应 400, 实际 %d", rec.Code)
	}
}

// ---- 明文密码旁路（AuthConfig.AllowPlaintextPassword，dev/test）----
//
// 浏览器在非安全上下文（非 https://、非 localhost）拿不到 WebCrypto，无法 RSA 加密。
// 旁路允许密码方式发 plain_credential 字段，handler 用 RSA 公钥就地加密喂给 signin password method。
// 验证码方式不受影响（验证码本就明文提交，不应被加密）。

func TestLogin_Password_PlaintextBypass_Allowed_Succeeds(t *testing.T) {
	f := newLoginFixtureAllowingPlaintext(t, true)
	const redirectURI = "http://127.0.0.1:5173/callback"
	f.seedAuthz(t, "lk1", redirectURI, "orig-plain")
	f.seedPasswordIdentity(t, "u@x.com", "usr_plain", "correct-pass")

	token, _ := f.csrf.Issue(context.Background(), "lk1")
	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":              {"lk1"},
		"csrf":            {token},
		"method":          {"password"},
		"identifier":      {"u@x.com"},
		"plain_credential": {"correct-pass"}, // credential 留空 → 走旁路
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("旁路开启 + plain_credential 应登录成功 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogin_Password_PlaintextBypass_Disabled_Rejects(t *testing.T) {
	f := newLoginFixtureAllowingPlaintext(t, false) // 模拟 prod/staging
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	f.seedPasswordIdentity(t, "u@x.com", "usr_reject", "correct-pass")

	token, _ := f.csrf.Issue(context.Background(), "lk1")
	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":              {"lk1"},
		"csrf":            {token},
		"method":          {"password"},
		"identifier":      {"u@x.com"},
		"plain_credential": {"correct-pass"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("旁路关闭时 plain_credential 应回渲 200, 实际 %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "明文") || !strings.Contains(body, "https://") {
		t.Errorf("应给出可读旁路拒绝提示, 实际: %s", body)
	}
}

func TestLogin_Password_EncryptedTakesPrecedenceOverPlaintext(t *testing.T) {
	f := newLoginFixtureAllowingPlaintext(t, true)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	f.seedPasswordIdentity(t, "u@x.com", "usr_both", "correct-pass")

	token, _ := f.csrf.Issue(context.Background(), "lk1")
	// encrypted 用正确密码 + plain 用错密码 → 走 encrypted 应当成功（验证 encrypted 优先）。
	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":              {"lk1"},
		"csrf":            {token},
		"method":          {"password"},
		"identifier":      {"u@x.com"},
		"credential":      {f.encryptPassword(t, "correct-pass")},
		"plain_credential": {"would-fail-if-used"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("encrypted_password 应优先并成功 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogin_CodeMethod_IgnoresPlaintextBypass(t *testing.T) {
	// 验证码方式：credential 即明文验证码，旁路逻辑不应介入。这里覆盖 method != "password"
	// 的分支：plain_credential 字段被忽略，credential 原样进 signin。
	f := newLoginFixtureAllowingPlaintext(t, true)
	f.seedAuthz(t, "lk1", "http://127.0.0.1:5173/callback", "orig")
	f.identities.byKey[model.IdentityTypeEmail+"|"+"c@x.com"] = &model.Identity{
		UUID: "idn_c", UserUUID: "usr_c", Type: model.IdentityTypeEmail, Identifier: "c@x.com",
	}
	// 直接写一条 OTP（绕过 send-code 流程）。
	_, _ = f.otp.Issue(context.Background(), "c@x.com", auth.PurposeLogin)
	rec := f.do(t, http.MethodPost, "/oauth/login", url.Values{
		"lk":              {"lk1"},
		"csrf":            {func() string { tk, _ := f.csrf.Issue(context.Background(), "lk1"); return tk }()},
		"method":          {"email_code"},
		"identifier":      {"c@x.com"},
		"credential":      {"000000"}, // 验证码错（OTP issue 后码未知），仅验证旁路不介入；不期望登录成功。
		"plain_credential": {"ignored-for-code-method"},
	})
	// 不应是 5xx；不应被旁路逻辑改写后导致解密失败崩溃。验证码方式逻辑路径不变。
	if rec.Code >= 500 {
		t.Fatalf("验证码方式不应被旁路影响导致 5xx, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}
