package router_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/cmd/wire"
	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// newPasswordEngine 装配一套注入内存身份/用户仓的引擎，并以固定 RSA 私钥构造解密器，
// 使测试能用配对公钥加密密码、走完整 router 级 HTTP 缝。返回引擎、miniredis（供 TTL 推进）与私钥。
func newPasswordEngine(t *testing.T, idRepo *memIdentityRepo) (*gin.Engine, *miniredis.Miniredis, *rsa.PrivateKey) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化 RSA 私钥失败: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	cfg := &config.Configuration{
		Env:      "test",
		Server:   config.ServerConfig{Addr: ":0", Mode: gin.TestMode},
		Redis:    config.RedisConfig{Addr: mr.Addr()},
		Postgres: config.PostgresConfig{DSN: "host=127.0.0.1 user=x dbname=x port=5432 sslmode=disable"},
		JWT:      config.JWTConfig{Secret: testSecret, Issuer: "vulture-gateway", AccessTTL: 30 * time.Minute},
		OAuth: config.OAuthConfig{
			ClientID:        "vulture-desktop",
			GatewayBaseURL:  "http://127.0.0.1:8080",
			GWCodeTTL:       60 * time.Second,
			AuthzTTL:        10 * time.Minute,
			PasswordLinkTTL: 5 * time.Minute,
		},
		Auth: config.AuthConfig{
			RSAPrivateKeyPEM:  privPEM,
			BcryptCost:        4, // 测试用低 cost 提速
			CSRFTTL:           10 * time.Minute,
			OTPTTL:            5 * time.Minute,
			OTPResendInterval: 60 * time.Second,
			OTPMaxAttempts:    5,
			LoginMaxFailures:  5,
			LoginLockWindow:   15 * time.Minute,
			SendMax:           5,
			SendWindow:        time.Hour,
		},
		ClawHub:  config.ClawHubConfig{BaseURL: "http://127.0.0.1:1", Timeout: 5 * time.Second},
		LLM:      config.LLMConfig{BaseURL: "http://127.0.0.1:1", MasterKey: "test-master", Timeout: 5 * time.Second},
		Scaffold: config.ScaffoldConfig{Enabled: true},
	}

	app, err := wire.WireApp(cfg, wire.WithIdentityRepository(idRepo), wire.WithUserRepository(memUserRepo{}), wire.WithTransactor(passthroughTx{}))
	if err != nil {
		t.Fatalf("WireApp 失败: %v", err)
	}
	return app.Engine, mr, priv
}

// encryptRSA 用公钥 RSA-OAEP(SHA-256) 加密明文，返回 base64（模拟浏览器 SubtleCrypto）。
func encryptRSA(t *testing.T, pub *rsa.PublicKey, plain string) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(plain), nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// doForm 发起 application/x-www-form-urlencoded 表单请求。
func doForm(t *testing.T, e *gin.Engine, method, path, bearer string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]*)"`)

// extractCSRF 从渲染页 HTML 提取 csrf 隐藏域值。
func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if len(m) != 2 || m[1] == "" {
		t.Fatalf("未能从页面提取 csrf: %s", body)
	}
	return m[1]
}

// mintLink 持 bearer 铸取 Password Link，返回其中的一次性 token（t）。
func mintLink(t *testing.T, e *gin.Engine, bearer string) string {
	t.Helper()
	rec := do(t, e, http.MethodPost, "/api/v1/auth/password-link", bearer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("password-link 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 password-link 响应失败: %v", err)
	}
	u, err := url.Parse(resp.URL)
	if err != nil {
		t.Fatalf("url 解析失败: %v", err)
	}
	tok := u.Query().Get("t")
	if tok == "" || u.Path != "/oauth/password" {
		t.Fatalf("url 不含 /oauth/password?t=: %q", resp.URL)
	}
	return tok
}

// ---- password-link 端点 ----

func TestPasswordLink_RequiresBearer(t *testing.T) {
	e, _, _ := newPasswordEngine(t, newMemIdentityRepo())

	if rec := do(t, e, http.MethodPost, "/api/v1/auth/password-link", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 Bearer 期望 401, 实际 %d", rec.Code)
	}
	if rec := do(t, e, http.MethodPost, "/api/v1/auth/password-link", "garbage.token", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("坏 Bearer 期望 401, 实际 %d", rec.Code)
	}

	token := issueViaScaffold(t, e, "usr_1", "dev_1")
	if rec := do(t, e, http.MethodPost, "/api/v1/auth/password-link", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("有效 Bearer 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

// ---- 绑定模式页渲染 ----

func TestPasswordPage_BindingMode(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_e2e", Type: model.IdentityTypeEmail, Identifier: "e2e@x.com"})
	e, _, _ := newPasswordEngine(t, idRepo)

	tok := mintLink(t, e, issueViaScaffold(t, e, "usr_e2e", "dev_e2e"))

	// 有效 t → 渲染绑定页：预填标识 + csrf。
	rec := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("有效 t 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "e2e@x.com") {
		t.Error("绑定页应预填标识 e2e@x.com")
	}
	extractCSRF(t, body) // 应含 csrf 隐藏域

	// 无 t → 登出态验证码模式页（#41），非绑定页：200 且让用户自填标识。
	if rec := do(t, e, http.MethodGet, "/oauth/password", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("无 t 期望 200 验证码模式页, 实际 %d", rec.Code)
	}
	// 伪造 t → 失效页。
	if rec := do(t, e, http.MethodGet, "/oauth/password?t=bogus", "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("伪造 t 期望 400, 实际 %d", rec.Code)
	}
}

func TestPasswordLink_TTLExpiry(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_e2e", Type: model.IdentityTypeEmail, Identifier: "e2e@x.com"})
	e, mr, _ := newPasswordEngine(t, idRepo)

	tok := mintLink(t, e, issueViaScaffold(t, e, "usr_e2e", "dev_e2e"))
	mr.FastForward(6 * time.Minute) // 超过 5 分钟 TTL

	if rec := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("过期 t 期望 400 失效页, 实际 %d", rec.Code)
	}
}

// ---- 端到端回路：首次设密码 → 账号级生效 → 新密码登录成功 ----

func TestSetPassword_AccountLevel_AndLoginRoundTrip(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_e2e", Type: model.IdentityTypeEmail, Identifier: "e2e@x.com"})
	idRepo.seed(&model.Identity{UUID: "idn_p", UserUUID: "usr_e2e", Type: model.IdentityTypePhone, Identifier: "13800000000"})
	// oauth 身份（provider 非空）：不应被写入密码。
	idRepo.seed(&model.Identity{UUID: "idn_o", UserUUID: "usr_e2e", Type: model.IdentityTypeOAuth, Identifier: "gh|42", Provider: "github"})
	e, _, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	const newPassword = "newpass123"

	// 1) 铸链 → 取页 csrf。
	tok := mintLink(t, e, issueViaScaffold(t, e, "usr_e2e", "dev_e2e"))
	pageRec := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil)
	csrf := extractCSRF(t, pageRec.Body.String())

	// 2) 浏览器内 RSA 加密提交新密码。
	setRec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t":                  {tok},
		"csrf":               {csrf},
		"encrypted_password": {encryptRSA(t, pub, newPassword)},
	})
	if setRec.Code != http.StatusOK || !strings.Contains(setRec.Body.String(), "设置成功") {
		t.Fatalf("设密码期望成功页 200, 实际 %d: %s", setRec.Code, setRec.Body.String())
	}

	// 3) 账号级：email 与 phone 的 secret 均被写入且相等；oauth 身份不写。
	emailSecret := idRepo.secretOf(model.IdentityTypeEmail, "e2e@x.com")
	phoneSecret := idRepo.secretOf(model.IdentityTypePhone, "13800000000")
	oauthSecret := idRepo.secretOf(model.IdentityTypeOAuth, "gh|42")
	if emailSecret == "" || phoneSecret == "" {
		t.Fatalf("email/phone secret 应被写入: email=%q phone=%q", emailSecret, phoneSecret)
	}
	if emailSecret != phoneSecret {
		t.Error("账号级密码：email 与 phone 应写入同一 hash")
	}
	if oauthSecret != "" {
		t.Errorf("oauth 身份不应被写入密码, 实际 %q", oauthSecret)
	}

	// 4) 单次有效：同一 t 再开 → 失效页。
	if rec := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("已用 t 再开期望 400 失效页, 实际 %d", rec.Code)
	}

	// 5) 端到端回路：用新密码经登录路径登录成功。
	lk := authorizeAndGetLinkedState(t, e)
	loginPage := do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk), "", nil)
	if loginPage.Code != http.StatusOK {
		t.Fatalf("登录页期望 200, 实际 %d", loginPage.Code)
	}
	loginCSRF := extractCSRF(t, loginPage.Body.String())

	loginRec := doForm(t, e, http.MethodPost, "/oauth/login", "", url.Values{
		"lk":         {lk},
		"method":     {"password"},
		"identifier": {"e2e@x.com"},
		"credential": {encryptRSA(t, pub, newPassword)},
		"csrf":       {loginCSRF},
	})
	if loginRec.Code != http.StatusFound {
		t.Fatalf("新密码登录期望 302 成功回跳, 实际 %d: %s", loginRec.Code, loginRec.Body.String())
	}
	if loc := loginRec.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("登录成功回跳应带 code, Location=%q", loc)
	}
}

// authorizeAndGetLinkedState 走 /oauth/authorize 拿到登录页 linkedState（lk）。
func authorizeAndGetLinkedState(t *testing.T, e *gin.Engine) string {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "vulture-desktop")
	q.Set("code_challenge", "challenge-abc")
	q.Set("code_challenge_method", "S256")
	q.Set("state", "orig-xyz")
	q.Set("redirect_uri", "http://127.0.0.1:5173/callback")

	rec := do(t, e, http.MethodGet, "/oauth/authorize?"+q.Encode(), "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize 期望 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	lk := loc.Query().Get("lk")
	if lk == "" {
		t.Fatal("authorize 回跳缺 lk")
	}
	return lk
}

// ---- 密码策略 ----

func TestSetPassword_WeakPassword_Rejected(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantMsg  string
	}{
		{"太短", "ab1", "8"},
		{"缺数字", "abcdefgh", "字母与数字"},
		{"缺字母", "12345678", "字母与数字"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idRepo := newMemIdentityRepo()
			idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_w", Type: model.IdentityTypeEmail, Identifier: "w@x.com"})
			e, _, priv := newPasswordEngine(t, idRepo)

			tok := mintLink(t, e, issueViaScaffold(t, e, "usr_w", "dev_w"))
			csrf := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil).Body.String())

			rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
				"t":                  {tok},
				"csrf":               {csrf},
				"encrypted_password": {encryptRSA(t, &priv.PublicKey, c.password)},
			})
			body := rec.Body.String()
			if strings.Contains(body, "设置成功") {
				t.Fatalf("弱密码不应成功: %s", body)
			}
			if !strings.Contains(body, c.wantMsg) {
				t.Errorf("应提示 %q, 实际: %s", c.wantMsg, body)
			}
			if idRepo.secretOf(model.IdentityTypeEmail, "w@x.com") != "" {
				t.Error("弱密码被拒后不应写入 secret")
			}
		})
	}
}

// ---- 反面：oauth-only 账号无本地标识 ----

func TestSetPassword_OAuthOnly_Friendly(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_o", UserUUID: "usr_o", Type: model.IdentityTypeOAuth, Identifier: "gh|7", Provider: "github"})
	e, _, _ := newPasswordEngine(t, idRepo)

	tok := mintLink(t, e, issueViaScaffold(t, e, "usr_o", "dev_o"))
	rec := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oauth-only 期望 400 友好拒绝, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "无法设置密码") {
		t.Errorf("应友好告知无法设置, 实际: %s", rec.Body.String())
	}
}

// ---- 改密（secret 非空）：需验证码二次确认（#40） ----

// pwresetCode 从 miniredis 直读某 dest 的 pwreset 验证码（绕过 stub sender 取真实码）。
func pwresetCode(t *testing.T, mr *miniredis.Miniredis, dest string) string {
	t.Helper()
	code, err := mr.Get("otp:pwreset:code:" + dest)
	if err != nil || code == "" {
		t.Fatalf("未能读取 pwreset 码 (dest=%s): %v", dest, err)
	}
	return code
}

// loginCodeOf 从 miniredis 直读某 dest 的 login 验证码（用于用途隔离反例）。
func loginCodeOf(t *testing.T, mr *miniredis.Miniredis, dest string) string {
	t.Helper()
	code, err := mr.Get("otp:login:code:" + dest)
	if err != nil || code == "" {
		t.Fatalf("未能读取 login 码 (dest=%s): %v", dest, err)
	}
	return code
}

// setInitialPwd 经 #39 绑定路径为该 User 设置首个密码（使其 secret 非空，进入改密态）。
func setInitialPwd(t *testing.T, e *gin.Engine, pub *rsa.PublicKey, userUUID, devID, pwd string) {
	t.Helper()
	tok := mintLink(t, e, issueViaScaffold(t, e, userUUID, devID))
	csrf := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil).Body.String())
	rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t":                  {tok},
		"csrf":               {csrf},
		"encrypted_password": {encryptRSA(t, pub, pwd)},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "设置成功") {
		t.Fatalf("前置设初始密码失败: %d %s", rec.Code, rec.Body.String())
	}
}

// resetPageCSRF 铸新链并取改密页 csrf；同时断言改密页处于「需验证码」模式。
func resetPageCSRF(t *testing.T, e *gin.Engine, userUUID, devID string) (tok, csrf string) {
	t.Helper()
	tok = mintLink(t, e, issueViaScaffold(t, e, userUUID, devID))
	page := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("改密页期望 200, 实际 %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	if !strings.Contains(body, "发送验证码") {
		t.Fatalf("已设密码账号的改密页应为验证码模式（含发送验证码）, 实际: %s", body)
	}
	return tok, extractCSRF(t, body)
}

func TestResetPassword_RequiresCode_AndLoginRoundTrip(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_r", Type: model.IdentityTypeEmail, Identifier: "r@x.com"})
	idRepo.seed(&model.Identity{UUID: "idn_p", UserUUID: "usr_r", Type: model.IdentityTypePhone, Identifier: "13900000000"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	const oldPassword = "oldpass123"
	const newPassword = "newpass456"
	setInitialPwd(t, e, pub, "usr_r", "dev_r", oldPassword)

	tok, csrf := resetPageCSRF(t, e, "usr_r", "dev_r")

	// 发改密验证码（页面作用域，靠 t 授权，非 Bearer）。
	scRec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{"t": {tok}})
	if scRec.Code != http.StatusOK {
		t.Fatalf("发改密码期望 200, 实际 %d: %s", scRec.Code, scRec.Body.String())
	}
	code := pwresetCode(t, mr, "r@x.com")

	// 正确码 → 改密成功，账号级写入（email 与 phone 同步更新为新 hash）。
	setRec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t":                  {tok},
		"csrf":               {csrf},
		"encrypted_password": {encryptRSA(t, pub, newPassword)},
		"code":               {code},
	})
	if setRec.Code != http.StatusOK || !strings.Contains(setRec.Body.String(), "成功") {
		t.Fatalf("改密期望成功页 200, 实际 %d: %s", setRec.Code, setRec.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "r@x.com") != idRepo.secretOf(model.IdentityTypePhone, "13900000000") {
		t.Error("账号级改密：email 与 phone 应写入同一新 hash")
	}

	// 端到端回路：新密码登录成功、旧密码登录失败。
	lk := authorizeAndGetLinkedState(t, e)
	loginCSRF := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk), "", nil).Body.String())
	okLogin := doForm(t, e, http.MethodPost, "/oauth/login", "", url.Values{
		"lk": {lk}, "method": {"password"}, "identifier": {"r@x.com"},
		"credential": {encryptRSA(t, pub, newPassword)}, "csrf": {loginCSRF},
	})
	if okLogin.Code != http.StatusFound {
		t.Fatalf("新密码登录期望 302, 实际 %d: %s", okLogin.Code, okLogin.Body.String())
	}

	lk2 := authorizeAndGetLinkedState(t, e)
	loginCSRF2 := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk2), "", nil).Body.String())
	badLogin := doForm(t, e, http.MethodPost, "/oauth/login", "", url.Values{
		"lk": {lk2}, "method": {"password"}, "identifier": {"r@x.com"},
		"credential": {encryptRSA(t, pub, oldPassword)}, "csrf": {loginCSRF2},
	})
	if badLogin.Code == http.StatusFound {
		t.Fatalf("旧密码登录应失败（非 302），实际 302 成功")
	}
}

func TestResetPassword_SendCode_ResendCooldown(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_c", Type: model.IdentityTypeEmail, Identifier: "c@x.com"})
	e, _, priv := newPasswordEngine(t, idRepo)
	setInitialPwd(t, e, &priv.PublicKey, "usr_c", "dev_c", "oldpass123")

	tok, _ := resetPageCSRF(t, e, "usr_c", "dev_c")

	// 首发成功。
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{"t": {tok}}); rec.Code != http.StatusOK {
		t.Fatalf("首发改密码期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	// 60s 内立即重发 → 429（重发冷却生效，pwreset 用途独立闸）。
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{"t": {tok}}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("60s 内重发期望 429, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResetPassword_MissingOrWrongCode_Rejected(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_m", Type: model.IdentityTypeEmail, Identifier: "m@x.com"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey
	setInitialPwd(t, e, pub, "usr_m", "dev_m", "oldpass123")
	oldHash := idRepo.secretOf(model.IdentityTypeEmail, "m@x.com")

	// 缺码：被拒，secret 不变。
	tok, csrf := resetPageCSRF(t, e, "usr_m", "dev_m")
	miss := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t": {tok}, "csrf": {csrf}, "encrypted_password": {encryptRSA(t, pub, "newpass456")},
	})
	if strings.Contains(miss.Body.String(), "成功") {
		t.Fatalf("缺码不应成功: %s", miss.Body.String())
	}
	if !strings.Contains(miss.Body.String(), "验证码") {
		t.Errorf("缺码应提示需验证码, 实际: %s", miss.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "m@x.com") != oldHash {
		t.Error("缺码被拒后 secret 不应改动")
	}

	// 错码：被拒，secret 不变（发码后用错码）。
	tok2, csrf2 := resetPageCSRF(t, e, "usr_m", "dev_m")
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{"t": {tok2}}); rec.Code != http.StatusOK {
		t.Fatalf("发码期望 200, 实际 %d", rec.Code)
	}
	_ = pwresetCode(t, mr, "m@x.com") // 确有真实码存在
	wrong := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t": {tok2}, "csrf": {csrf2}, "encrypted_password": {encryptRSA(t, pub, "newpass456")}, "code": {"000000"},
	})
	if strings.Contains(wrong.Body.String(), "成功") {
		t.Fatalf("错码不应成功: %s", wrong.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "m@x.com") != oldHash {
		t.Error("错码被拒后 secret 不应改动")
	}
}

func TestResetPassword_PurposeIsolation_LoginCodeRejected(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_i", Type: model.IdentityTypeEmail, Identifier: "i@x.com"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey
	setInitialPwd(t, e, pub, "usr_i", "dev_i", "oldpass123")
	oldHash := idRepo.secretOf(model.IdentityTypeEmail, "i@x.com")

	// 为 i@x.com 取一枚 login 用途的验证码（经登录页发码端点）。
	lk := authorizeAndGetLinkedState(t, e)
	if rec := doForm(t, e, http.MethodPost, "/oauth/send-code", "", url.Values{
		"lk": {lk}, "method": {"email_code"}, "identifier": {"i@x.com"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("登录发码期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loginCode := loginCodeOf(t, mr, "i@x.com")

	// 用 login 码去改密：用途隔离 → 应被拒，secret 不变。
	tok, csrf := resetPageCSRF(t, e, "usr_i", "dev_i")
	rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t": {tok}, "csrf": {csrf}, "encrypted_password": {encryptRSA(t, pub, "newpass456")}, "code": {loginCode},
	})
	if strings.Contains(rec.Body.String(), "成功") {
		t.Fatalf("login 码不应能用于 pwreset 改密: %s", rec.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "i@x.com") != oldHash {
		t.Error("用途隔离拒绝后 secret 不应改动")
	}
}

func TestResetPassword_RateLimitLock(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_l", Type: model.IdentityTypeEmail, Identifier: "l@x.com"})
	e, _, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey
	setInitialPwd(t, e, pub, "usr_l", "dev_l", "oldpass123")
	oldHash := idRepo.secretOf(model.IdentityTypeEmail, "l@x.com")

	// 连续 5 次错码（LoginMaxFailures=5）→ 触顶锁定。
	for i := 0; i < 5; i++ {
		tok, csrf := resetPageCSRF(t, e, "usr_l", "dev_l")
		doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
			"t": {tok}, "csrf": {csrf}, "encrypted_password": {encryptRSA(t, pub, "newpass456")}, "code": {"000000"},
		})
	}

	// 触顶后即便给「会成功的」上下文也应被锁定拒绝，secret 始终不变。
	tok, csrf := resetPageCSRF(t, e, "usr_l", "dev_l")
	locked := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"t": {tok}, "csrf": {csrf}, "encrypted_password": {encryptRSA(t, pub, "newpass456")}, "code": {"000000"},
	})
	if strings.Contains(locked.Body.String(), "成功") {
		t.Fatalf("锁定后不应成功: %s", locked.Body.String())
	}
	if !strings.Contains(locked.Body.String(), "频繁") {
		t.Errorf("锁定后应提示尝试过于频繁, 实际: %s", locked.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "l@x.com") != oldHash {
		t.Error("锁定全程 secret 不应改动")
	}
}
