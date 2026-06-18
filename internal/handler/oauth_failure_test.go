package handler_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// authorizeLinkedState 走 authorize 一步，返回跳上游时携带的关联 state。
func (f *oauthFixture) authorizeLinkedState(t *testing.T, redirectURI, origState string) string {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "vulture-desktop")
	q.Set("code_challenge", challengeFor(pkceVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", origState)
	q.Set("redirect_uri", redirectURI)
	rec := f.get(t, "/oauth/authorize?"+q.Encode())
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize 期望 302, 实际 %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	return loc.Query().Get("state")
}

// 用户在上游取消（error=access_denied）+ state 有效 → 302 回跳带 error=access_denied + 原 state。
func TestCallback_UserCancelled_RedirectsAccessDenied(t *testing.T) {
	f := newOAuthFixture(t)
	redirectURI := "http://127.0.0.1:5173/callback"
	linked := f.authorizeLinkedState(t, redirectURI, "orig-cancel")

	rec := f.get(t, "/oauth/callback/casdoor?error=access_denied&state="+url.QueryEscape(linked))
	if rec.Code != http.StatusFound {
		t.Fatalf("取消应 302 回跳, 实际 %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != redirectURI {
		t.Errorf("应回跳 %s, 实际 %s", redirectURI, loc.String())
	}
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("error 应为 access_denied, 实际 %q", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "orig-cancel" {
		t.Errorf("应带回原 state, 实际 %q", loc.Query().Get("state"))
	}
}

// 上游其它错误（非取消）→ 归一为 server_error 回跳。
func TestCallback_OtherUpstreamError_NormalizesServerError(t *testing.T) {
	f := newOAuthFixture(t)
	redirectURI := "http://127.0.0.1:5173/callback"
	linked := f.authorizeLinkedState(t, redirectURI, "orig-x")

	rec := f.get(t, "/oauth/callback/casdoor?error=temporarily_unavailable&state="+url.QueryEscape(linked))
	if rec.Code != http.StatusFound {
		t.Fatalf("期望 302, 实际 %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "server_error" {
		t.Errorf("非取消错误应归一 server_error, 实际 %q", loc.Query().Get("error"))
	}
}

// state 失效/非法 → 渲染极简错误页（HTML），不回跳（无 Location）。
func TestCallback_InvalidState_RendersErrorPage(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.get(t, "/oauth/callback/casdoor?code=c&state=st_unknown")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("失效 state 期望 400, 实际 %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("不应回跳, 却有 Location=%q", loc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("应渲染 HTML 错误页, Content-Type=%q", ct)
	}
	if !strings.Contains(rec.Body.String(), "登录失败") {
		t.Errorf("错误页应含提示, body=%s", rec.Body.String())
	}
}

// 缺失 state → 同样渲染错误页（无法定位 redirect_uri）。
func TestCallback_MissingState_RendersErrorPage(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.get(t, "/oauth/callback/casdoor?code=c")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 state 期望 400, 实际 %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("不应回跳")
	}
}

// 三族错误体分流：同一「未授权/失败」在三族各呈其形。
func TestErrorBodyFamilies(t *testing.T) {
	f := newOAuthFixture(t)

	// /oauth/*：RFC 6749 {error, error_description}。
	t.Run("oauth", func(t *testing.T) {
		rec := f.refresh(t, "rt_unknown")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("期望 401, 实际 %d", rec.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if _, ok := body["error"].(string); !ok {
			t.Errorf("/oauth/* error 应为字符串, body=%s", rec.Body.String())
		}
		if _, ok := body["error_description"]; !ok {
			t.Errorf("/oauth/* 应含 error_description, body=%s", rec.Body.String())
		}
	})

	// /api/v1/*：ApiError{error, message}（真实状态码）。
	t.Run("api_v1", func(t *testing.T) {
		rec := f.authReq(http.MethodGet, "/api/v1/whoami", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("期望 401, 实际 %d", rec.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if _, ok := body["error"].(string); !ok {
			t.Errorf("/api/v1/* error 应为字符串, body=%s", rec.Body.String())
		}
		if _, ok := body["message"]; !ok {
			t.Errorf("/api/v1/* 应含 message, body=%s", rec.Body.String())
		}
	})

	// /v1/*：OpenAI {error:{message, type, code}}。
	t.Run("v1_llm", func(t *testing.T) {
		rec := f.authReq(http.MethodGet, "/v1/ping", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("期望 401, 实际 %d", rec.Code)
		}
		var body struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("解析 OpenAI 错误体失败: %v", err)
		}
		if body.Error.Type == "" || body.Error.Message == "" {
			t.Errorf("/v1/* 应呈 OpenAI 嵌套 error 体, body=%s", rec.Body.String())
		}
	})
}
