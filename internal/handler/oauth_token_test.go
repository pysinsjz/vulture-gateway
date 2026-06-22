package handler_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
)

const pkceVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *oauthFixture) postJSON(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec
}

// obtainGWCode 直接向 GWCodeStore 播种一枚 GW_CODE（绑定给定 challenge / redirect_uri），
// 等价于自建登录页提交成功后的签发结果——A1 下半 /oauth/token 用例与登录方式解耦。
func (f *oauthFixture) obtainGWCode(t *testing.T, challenge, redirectURI string) string {
	t.Helper()
	gw, err := f.gwcodes.Issue(context.Background(), auth.GWCode{
		CodeChallenge: challenge,
		UserUUID:      "usr_test",
		RedirectURI:   redirectURI,
	})
	if err != nil {
		t.Fatalf("播种 GW_CODE 失败: %v", err)
	}
	return gw
}

func tokenBody(code, verifier, redirectURI string) map[string]any {
	return map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": verifier,
		"client_id":     "vulture-desktop",
		"redirect_uri":  redirectURI,
		"device":        map[string]any{"name": "Pan's Mac", "os": "macOS 15.5", "app_version": "1.2.0"},
	}
}

func assertOAuthError(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 OAuth 错误体: %v (body=%s)", err, rec.Body.String())
	}
	if body.Error != wantCode {
		t.Errorf("error = %q, 期望 %q (body=%s)", body.Error, wantCode, rec.Body.String())
	}
}

// 正路 + 首次登录闭环：换码成功 → 创建 Device + refresh → access 能跑通 JWTAuth。
func TestToken_AuthorizationCode_FullLoginLoop(t *testing.T) {
	f := newOAuthFixture(t)
	redirectURI := "http://127.0.0.1:5173/callback"
	gw := f.obtainGWCode(t, challengeFor(pkceVerifier), redirectURI)

	rec := f.postJSON(t, "/oauth/token", tokenBody(gw, pkceVerifier, redirectURI))
	if rec.Code != http.StatusOK {
		t.Fatalf("token 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		DeviceID     string `json:"device_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 token 响应失败: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" || resp.DeviceID == "" || resp.TokenType != "Bearer" || resp.ExpiresIn <= 0 {
		t.Fatalf("token 响应字段缺失: %+v", resp)
	}

	// 创建了一台 Device + 一条 refresh，且 device_id 一致。
	if len(f.devices.created) != 1 || f.devices.created[0].UUID != resp.DeviceID {
		t.Errorf("应创建 1 台 Device 且 device_id 一致, 实际 %+v", f.devices.created)
	}
	if len(f.refreshes.created) != 1 || f.refreshes.created[0].DeviceUUID != resp.DeviceID {
		t.Errorf("应创建 1 条 refresh 并绑定 device, 实际 %+v", f.refreshes.created)
	}
	if f.devices.created[0].Name != "Pan's Mac" {
		t.Errorf("Device 元信息未落库: %+v", f.devices.created[0])
	}

	// 闭环：换得的 access JWT 访问受保护端点应 200。
	whoami := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	whoami.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	whoRec := httptest.NewRecorder()
	f.engine.ServeHTTP(whoRec, whoami)
	if whoRec.Code != http.StatusOK {
		t.Fatalf("换得的 access 访问 whoami 期望 200, 实际 %d: %s", whoRec.Code, whoRec.Body.String())
	}
}

// PKCE 不匹配 → 400 invalid_grant。
func TestToken_PKCEMismatch(t *testing.T) {
	f := newOAuthFixture(t)
	redirectURI := "http://127.0.0.1:5173/callback"
	gw := f.obtainGWCode(t, challengeFor(pkceVerifier), redirectURI)

	rec := f.postJSON(t, "/oauth/token", tokenBody(gw, "wrong-verifier", redirectURI))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("期望 400, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// GW_CODE 复用 → 第二次 400 invalid_grant。
func TestToken_GWCodeReuse(t *testing.T) {
	f := newOAuthFixture(t)
	redirectURI := "http://127.0.0.1:5173/callback"
	gw := f.obtainGWCode(t, challengeFor(pkceVerifier), redirectURI)

	if rec := f.postJSON(t, "/oauth/token", tokenBody(gw, pkceVerifier, redirectURI)); rec.Code != http.StatusOK {
		t.Fatalf("首次换码应 200, 实际 %d", rec.Code)
	}
	rec := f.postJSON(t, "/oauth/token", tokenBody(gw, pkceVerifier, redirectURI))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("复用 GW_CODE 期望 400, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// redirect_uri 不一致 → 400 invalid_grant。
func TestToken_RedirectURIMismatch(t *testing.T) {
	f := newOAuthFixture(t)
	gw := f.obtainGWCode(t, challengeFor(pkceVerifier), "http://127.0.0.1:5173/callback")

	rec := f.postJSON(t, "/oauth/token", tokenBody(gw, pkceVerifier, "http://127.0.0.1:9999/callback"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("期望 400, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// 未知 GW_CODE → 400 invalid_grant。
func TestToken_UnknownCode(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.postJSON(t, "/oauth/token", tokenBody("gwc_unknown", pkceVerifier, "http://127.0.0.1:5173/callback"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("期望 400, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// client_id 错误 → 400 invalid_client。
func TestToken_WrongClientID(t *testing.T) {
	f := newOAuthFixture(t)
	redirectURI := "http://127.0.0.1:5173/callback"
	gw := f.obtainGWCode(t, challengeFor(pkceVerifier), redirectURI)

	body := tokenBody(gw, pkceVerifier, redirectURI)
	body["client_id"] = "someone-else"
	rec := f.postJSON(t, "/oauth/token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("期望 400, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_client")
}
