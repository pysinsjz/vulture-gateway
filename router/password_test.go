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
			RSAPrivateKeyPEM: privPEM,
			BcryptCost:       4, // 测试用低 cost 提速
			CSRFTTL:          10 * time.Minute,
			OTPTTL:           5 * time.Minute,
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

	// 无 t → 失效页（400），非空白/500。
	if rec := do(t, e, http.MethodGet, "/oauth/password", "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("无 t 期望 400, 实际 %d", rec.Code)
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

// ---- 改密（secret 非空）不在本切片范围：拒绝 ----

func TestSetPassword_AlreadySet_OutOfScope(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_s", Type: model.IdentityTypeEmail, Identifier: "s@x.com", Secret: "existing-hash"})
	e, _, _ := newPasswordEngine(t, idRepo)

	tok := mintLink(t, e, issueViaScaffold(t, e, "usr_s", "dev_s"))

	// GET：已设密码 → 失效页（首设入口对其不可用）。
	getRec := do(t, e, http.MethodGet, "/oauth/password?t="+url.QueryEscape(tok), "", nil)
	if getRec.Code != http.StatusBadRequest || !strings.Contains(getRec.Body.String(), "已设置密码") {
		t.Fatalf("已设密码 GET 期望 400 提示改密未开放, 实际 %d: %s", getRec.Code, getRec.Body.String())
	}

	// 既有 secret 不被改动。
	if idRepo.secretOf(model.IdentityTypeEmail, "s@x.com") != "existing-hash" {
		t.Error("首设入口不应改动已有密码")
	}
}
