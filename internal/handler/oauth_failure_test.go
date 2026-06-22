package handler_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// 注：上游回调（/oauth/callback/casdoor）失败回跳与错误页用例随 Casdoor 删除下线（ADR-0013）；
// 登录失败语义改由阶段五自建登录页用例覆盖。本文件保留与上游无关的三族错误体分流契约测试。

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
