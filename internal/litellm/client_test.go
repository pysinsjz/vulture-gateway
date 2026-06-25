package litellm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

// 正路：ListModels 代理 litellm /v1/models，注入 virtual key，原样返回上游状态/头/体。
func TestListModels_ProxiesAndInjectsKey(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Litellm-Call-Id", "call-1")
		w.Header().Set("X-Litellm-Response-Cost", "0.01")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4","object":"model"}]}`))
	}))
	defer srv.Close()

	c := litellm.NewHTTPClient(srv.URL, srv.Client())
	res, err := c.ListModels(context.Background(), "secret-vkey")
	if err != nil {
		t.Fatalf("ListModels 失败: %v", err)
	}
	if gotPath != "/v1/models" {
		t.Errorf("路径 = %q, 期望 /v1/models", gotPath)
	}
	if gotAuth != "Bearer secret-vkey" {
		t.Errorf("应注入 virtual key, 实际 Authorization=%q", gotAuth)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, 期望 200", res.Status)
	}
	// 原始头保留（脱敏在 handler 层）。
	if res.Header.Get("X-Litellm-Response-Cost") == "" {
		t.Error("client 不脱敏：成本头应原样在 ProxyResult.Header 中")
	}
}

// 空 virtual key：不注入 Authorization（本地无鉴权 litellm）。
func TestListModels_NoKeyNoAuthHeader(t *testing.T) {
	var hadAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer srv.Close()

	c := litellm.NewHTTPClient(srv.URL, srv.Client())
	if _, err := c.ListModels(context.Background(), ""); err != nil {
		t.Fatalf("ListModels 失败: %v", err)
	}
	if hadAuth {
		t.Error("空 key 不应带 Authorization 头")
	}
}

// 上游非 2xx 也原样返回（OpenAI 错误体由 handler 透传）。
func TestListModels_PassesThroughUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate","type":"rate_limit_error","code":"x"}}`))
	}))
	defer srv.Close()

	c := litellm.NewHTTPClient(srv.URL, srv.Client())
	res, err := c.ListModels(context.Background(), "")
	if err != nil {
		t.Fatalf("上游错误不应作为 transport error: %v", err)
	}
	if res.Status != http.StatusTooManyRequests {
		t.Errorf("应原样返回 429, 实际 %d", res.Status)
	}
}

// 传输失败（litellm 不可达）返回 error，由 handler 收敛为 OpenAI 502。
func TestListModels_TransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := litellm.NewHTTPClient(url, &http.Client{})
	if _, err := c.ListModels(context.Background(), ""); err == nil {
		t.Fatal("期望传输错误, 实际 nil")
	}
}
