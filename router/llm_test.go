package router_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pysinsjz/vulture-gateway/config"
)

func withLLM(url string) func(*config.Configuration) {
	return func(cfg *config.Configuration) { cfg.LLM.BaseURL = url }
}

// assertOpenAIError 断言响应体为 OpenAI 形态 {error:{message,type,code}}。
func assertOpenAIError(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 OpenAI 错误体: %v (body=%s)", err, rec.Body.String())
	}
	if body.Error.Type == "" {
		t.Errorf("OpenAI error.type 为空 (body=%s)", rec.Body.String())
	}
	if wantCode != "" && body.Error.Code != wantCode {
		t.Errorf("error.code = %q, 期望 %q", body.Error.Code, wantCode)
	}
}

// stubLitellm 是桩 litellm，记录收到的 Authorization（验证网关注入 virtual key）。
func stubLitellm(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Litellm-Call-Id", "call-xyz")
		w.Header().Set("X-Litellm-Response-Cost", "0.0042")
		w.Header().Set("llm_provider-region", "us-east")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4","object":"model"},{"id":"claude-opus","object":"model"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth
}

// 正路：合法 Bearer → 200 ModelList 透传；成本头剥除、x-litellm-call-id 保留；网关注入 virtual key。
func TestModels_HappyPath(t *testing.T) {
	srv, gotAuth := stubLitellm(t)
	e := newTestEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/v1/models", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}

	var list struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("解析 ModelList 失败: %v (%s)", err, rec.Body.String())
	}
	if list.Object != "list" || len(list.Data) != 2 || list.Data[0].ID != "gpt-4" {
		t.Fatalf("ModelList 形态错误: %+v", list)
	}

	// 成本头剥除、call-id 保留。
	if rec.Header().Get("X-Litellm-Response-Cost") != "" || rec.Header().Get("llm_provider-region") != "" {
		t.Errorf("成本敏感头未剥除: cost=%q provider=%q", rec.Header().Get("X-Litellm-Response-Cost"), rec.Header().Get("llm_provider-region"))
	}
	if rec.Header().Get("X-Litellm-Call-Id") != "call-xyz" {
		t.Errorf("x-litellm-call-id 应保留, 实际 %q", rec.Header().Get("X-Litellm-Call-Id"))
	}

	// 桌面端拿不到 litellm key：网关用自己的 virtual key 转发（非客户端 JWT）。
	if *gotAuth != "Bearer test-vkey" {
		t.Errorf("网关应注入 virtual key, litellm 实际收到 Authorization=%q", *gotAuth)
	}
}

// 鉴权负路：缺失/非法 token → OpenAI 形态 401，不触达 litellm。
func TestModels_Unauthorized(t *testing.T) {
	srv, _ := stubLitellm(t)
	e := newTestEngine(t, withLLM(srv.URL))

	for name, token := range map[string]string{"缺失": "", "垃圾串": "garbage.token"} {
		t.Run(name, func(t *testing.T) {
			rec := do(t, e, http.MethodGet, "/v1/models", token, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("期望 401, 实际 %d: %s", rec.Code, rec.Body.String())
			}
			assertOpenAIError(t, rec, "unauthorized")
		})
	}
}

// 被吊销 Device（bump token_version 后）→ OpenAI 形态 403 device_revoked。
func TestModels_RevokedDevice403(t *testing.T) {
	srv, _ := stubLitellm(t)
	e := newTestEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	// 吊销前可用。
	if rec := do(t, e, http.MethodGet, "/v1/models", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("吊销前期望 200, 实际 %d", rec.Code)
	}

	// bump → token_version 自增。
	if rec := do(t, e, http.MethodPost, "/__dev/bump", "", map[string]any{"device_id": "dev-llm"}); rec.Code != http.StatusOK {
		t.Fatalf("/__dev/bump 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}

	// 原 token 被吊销 → 403 device_revoked（区别于 401 鉴权失败）。
	rec := do(t, e, http.MethodGet, "/v1/models", token, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("吊销后期望 403, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "device_revoked")
}

// litellm 不可达 → OpenAI 形态 502。
func TestModels_UpstreamUnreachable(t *testing.T) {
	e := newTestEngine(t, withLLM("http://127.0.0.1:1"))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/v1/models", token, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "")
}
