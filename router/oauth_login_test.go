package router_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// authorize 合法参数经完整 WireApp 装配后应 302 跳网关登录页 /oauth/login（ADR-0013，替代原跳 Casdoor）。
func TestAuthorize_RedirectsToGatewayLoginPage(t *testing.T) {
	engine := newTestEngine(t)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "vulture-desktop")
	q.Set("code_challenge", "challenge-abc")
	q.Set("code_challenge_method", "S256")
	q.Set("state", "orig-xyz")
	q.Set("redirect_uri", "http://127.0.0.1:5173/callback")

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("期望 302, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/oauth/login" {
		t.Errorf("应跳网关登录页 /oauth/login, 实际 %s", loc.Path)
	}
	if loc.Query().Get("lk") == "" {
		t.Error("跳登录页应带 linkedState（lk）")
	}
}

// 登录页路由已接上：无效 lk 走 handler 渲染错误页（400），而非 404 未注册。
func TestLoginPage_RouteWired(t *testing.T) {
	engine := newTestEngine(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/login?lk=nope", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatal("/oauth/login 未注册（404）")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无效 lk 期望 400 错误页, 实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "登录失败") {
		t.Error("应渲染错误页")
	}
}
