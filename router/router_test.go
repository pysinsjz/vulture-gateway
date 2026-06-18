package router_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/pysinsjz/vulture-gateway/cmd/wire"
	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/auth"
)

const testSecret = "contract-test-secret"

// newTestEngine 用 miniredis 装配一套完整引擎（开启脚手架端点），返回引擎。
// opts 可在装配前微调配置（如把 ClawHub 基址指向 httptest 桩，见 plugin_test.go）。
func newTestEngine(t *testing.T, opts ...func(*config.Configuration)) *gin.Engine {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)

	cfg := &config.Configuration{
		Env:      "test",
		Server:   config.ServerConfig{Addr: ":0", Mode: gin.TestMode},
		Redis:    config.RedisConfig{Addr: mr.Addr()},
		Postgres: config.PostgresConfig{DSN: "host=127.0.0.1 user=x dbname=x port=5432 sslmode=disable"},
		JWT:      config.JWTConfig{Secret: testSecret, Issuer: "vulture-gateway", AccessTTL: 30 * time.Minute},
		OAuth: config.OAuthConfig{
			ClientID:       "vulture-desktop",
			GatewayBaseURL: "http://127.0.0.1:8080",
			GWCodeTTL:      60 * time.Second,
			AuthzTTL:       10 * time.Minute,
			Upstream:       config.UpstreamConfig{Mode: "stub", AuthorizeURL: "http://127.0.0.1:8080/oauth/_stub/authorize", ClientID: "vulture-gateway", Scopes: "openid profile"},
		},
		// 默认指向不可达基址；未调 /plugins 的用例不会触达。需正路的用例用 opts 覆盖为桩 URL。
		ClawHub:  config.ClawHubConfig{BaseURL: "http://127.0.0.1:1", Timeout: 5 * time.Second},
		Scaffold: config.ScaffoldConfig{Enabled: true},
	}
	for _, o := range opts {
		o(cfg)
	}
	app, err := wire.WireApp(cfg)
	if err != nil {
		t.Fatalf("WireApp 失败: %v", err)
	}
	return app.Engine
}

// signToken 用测试密钥直接签发一枚 access JWT，便于构造过期/异签等边界 token。
func signToken(t *testing.T, secret, sub, deviceID string, tokenVersion int64, expiresAt time.Time) string {
	t.Helper()
	claims := auth.AccessClaims{
		DeviceID:     deviceID,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    "vulture-gateway",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("签发测试 token 失败: %v", err)
	}
	return signed
}

func do(t *testing.T, e *gin.Engine, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// issueViaScaffold 走 /__dev/token 端点内部签发，返回 access_token。
func issueViaScaffold(t *testing.T, e *gin.Engine, sub, deviceID string) string {
	t.Helper()
	rec := do(t, e, http.MethodPost, "/__dev/token", "", map[string]any{"sub": sub, "device_id": deviceID})
	if rec.Code != http.StatusOK {
		t.Fatalf("/__dev/token 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 token 响应失败: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("access_token 为空")
	}
	return resp.AccessToken
}

func assertApiError(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 ApiError JSON: %v (body=%s)", err, rec.Body.String())
	}
	if body.Error == "" {
		t.Errorf("ApiError.error 为空 (body=%s)", rec.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	e := newTestEngine(t)
	rec := do(t, e, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz 期望 200, 实际 %d", rec.Code)
	}
}

// 合法 access JWT 访问受保护探针 → 200，并正确解析 claims。
func TestWhoami_ValidToken(t *testing.T) {
	e := newTestEngine(t)
	token := issueViaScaffold(t, e, "user-42", "dev-42")

	rec := do(t, e, http.MethodGet, "/api/v1/whoami", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("whoami 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Sub      string `json:"sub"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 whoami 响应失败: %v", err)
	}
	if resp.Sub != "user-42" || resp.DeviceID != "dev-42" {
		t.Errorf("claims 解析错误: sub=%q device_id=%q", resp.Sub, resp.DeviceID)
	}
}

// 缺失/非法/过期/签名错误的 token → 401 + ApiError。
func TestWhoami_RejectsBadTokens(t *testing.T) {
	e := newTestEngine(t)

	expired := signToken(t, testSecret, "user-1", "dev-1", 1, time.Now().Add(-time.Hour))
	badSig := signToken(t, "wrong-secret", "user-1", "dev-1", 1, time.Now().Add(time.Hour))

	cases := map[string]string{
		"缺失":   "",
		"垃圾串":  "garbage.token.value",
		"过期":   expired,
		"签名错误": badSig,
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, e, http.MethodGet, "/api/v1/whoami", token, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("期望 401, 实际 %d: %s", rec.Code, rec.Body.String())
			}
			assertApiError(t, rec)
		})
	}
}

// 缺失 Authorization 头（连 Bearer 前缀都没有）→ 401 + ApiError。
func TestWhoami_MissingHeader(t *testing.T) {
	e := newTestEngine(t)
	rec := do(t, e, http.MethodGet, "/api/v1/whoami", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401, 实际 %d", rec.Code)
	}
	assertApiError(t, rec)
}

// bump 对应 Device 的 token_version 后，原 access JWT 立即 401（即时吊销）。
func TestWhoami_InstantRevocationAfterBump(t *testing.T) {
	e := newTestEngine(t)
	token := issueViaScaffold(t, e, "user-7", "dev-7")

	// 吊销前可用。
	if rec := do(t, e, http.MethodGet, "/api/v1/whoami", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("吊销前 whoami 期望 200, 实际 %d", rec.Code)
	}

	// bump → token_version 自增。
	if rec := do(t, e, http.MethodPost, "/__dev/bump", "", map[string]any{"device_id": "dev-7"}); rec.Code != http.StatusOK {
		t.Fatalf("/__dev/bump 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}

	// 原 token 立即失效。
	rec := do(t, e, http.MethodGet, "/api/v1/whoami", token, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("吊销后 whoami 期望 401, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertApiError(t, rec)
}

// JWTAuth 对公开例外路径放行、不要求 Bearer。
func TestPublicExceptions_NoBearer(t *testing.T) {
	e := newTestEngine(t)
	for _, path := range []string{"/api/v1/bootstrap", "/api/v1/app/latest"} {
		t.Run(path, func(t *testing.T) {
			rec := do(t, e, http.MethodGet, path, "", nil)
			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("公开例外 %s 不应 401, 实际 %d", path, rec.Code)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("公开例外 %s 期望 200, 实际 %d", path, rec.Code)
			}
		})
	}
}
