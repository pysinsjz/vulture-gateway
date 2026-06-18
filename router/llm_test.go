package router_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// ===== D2 流式推理（#24）=====

// withLLMIdle 把 LLM 基址指向桩并调小流式空闲超时，便于断流测试。
func withLLMIdle(url string, idle time.Duration) func(*config.Configuration) {
	return func(cfg *config.Configuration) {
		cfg.LLM.BaseURL = url
		cfg.LLM.StreamIdleTimeout = idle
	}
}

// sseWrite 写一个 SSE chunk 并 flush。
func sseWrite(w http.ResponseWriter, fl http.Flusher, line string) {
	_, _ = io.WriteString(w, line)
	fl.Flush()
}

// 正路：stream:true → 网关强制注入 include_usage、SSE 逐 chunk 透传、保留 call-id、剥成本头、注入 virtual key。
func TestChatCompletions_StreamingPassthroughAndInjectsUsage(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Litellm-Call-Id", "call-77")
		w.Header().Set("X-Litellm-Response-Cost", "0.0042")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		sseWrite(w, fl, "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n")
		sseWrite(w, fl, "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n")
		sseWrite(w, fl, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":3,\"total_tokens\":15}}\n\n")
		sseWrite(w, fl, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)

	e := newTestEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, map[string]any{
		"model":    "gpt-4",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
		"stream":   true,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"content":"Hel"`, `"content":"lo"`, `"total_tokens":15`, "data: [DONE]"} {
		if !strings.Contains(body, want) {
			t.Errorf("SSE 输出缺 %q\n实际: %s", want, body)
		}
	}
	// 网关强制注入 include_usage（客户端未传 stream_options）。
	includeUsage := false
	if so, ok := gotBody["stream_options"].(map[string]any); ok {
		includeUsage, _ = so["include_usage"].(bool)
	}
	if !includeUsage {
		t.Errorf("网关应强制注入 stream_options.include_usage=true, 桩收到 body=%v", gotBody)
	}
	if gotAuth != "Bearer test-vkey" {
		t.Errorf("应注入 virtual key, 桩收到 Authorization=%q", gotAuth)
	}
	if rec.Header().Get("X-Litellm-Call-Id") != "call-77" {
		t.Error("x-litellm-call-id 应保留透传")
	}
	if rec.Header().Get("X-Litellm-Response-Cost") != "" {
		t.Error("成本头应被剥除")
	}
}

// 非流式：stream:false → 不注入 stream_options，返回 JSON 且 usage 在体内。
func TestChatCompletions_NonStreamingJSON(t *testing.T) {
	var sawStreamOptions bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		_, sawStreamOptions = m["stream_options"]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"c1","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	t.Cleanup(srv.Close)

	e := newTestEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, map[string]any{
		"model":    "gpt-4",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
		"stream":   false,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if sawStreamOptions {
		t.Error("非流式不应注入 stream_options（OpenAI 对此会 400）")
	}
	if !strings.Contains(rec.Body.String(), `"total_tokens":7`) {
		t.Errorf("非流式 usage 应在响应体内, 实际 %s", rec.Body.String())
	}
}

// usage chunk 缺失：仍 200、以 [DONE] 收尾、不崩溃、不误阻断。
func TestChatCompletions_MissingUsageChunkTolerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		sseWrite(w, fl, "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n")
		sseWrite(w, fl, "data: [DONE]\n\n") // 无 usage chunk
	}))
	t.Cleanup(srv.Close)

	e := newTestEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": true,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data: [DONE]") || !strings.Contains(body, `"content":"x"`) {
		t.Errorf("缺 usage 仍应完整透传 chunk + [DONE], 实际 %s", body)
	}
}

// 上游错误：litellm 返 400 OpenAI 错误体 → 网关原样透传状态码与体。
func TestChatCompletions_UpstreamErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad model","type":"invalid_request_error","code":"model_not_found"}}`))
	}))
	t.Cleanup(srv.Close)

	e := newTestEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, map[string]any{
		"model": "nope", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": true,
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("应透传上游 400, 实际 %d", rec.Code)
	}
	assertOpenAIError(t, rec, "model_not_found")
}

// 空闲超时：首 chunk 后上游久停 → 网关空闲超时中断（已发部分到达、[DONE] 未到）。
func TestChatCompletions_IdleTimeoutAbortsStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		sseWrite(w, fl, "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
		time.Sleep(400 * time.Millisecond) // > idle，触发网关中断
		sseWrite(w, fl, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)

	e := newTestEngine(t, withLLMIdle(srv.URL, 80*time.Millisecond))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": true,
	})

	body := rec.Body.String()
	if !strings.Contains(body, `"content":"partial"`) {
		t.Errorf("中断前已生成部分应到达, 实际 %s", body)
	}
	if strings.Contains(body, "data: [DONE]") {
		t.Errorf("空闲超时应在 [DONE] 前中断, 实际 %s", body)
	}
}

// 无 Bearer → 401，OpenAI 错误体形态（JWTAuthLLM 覆盖 chat 端点）。
func TestChatCompletions_NoTokenUnauthorized(t *testing.T) {
	e := newTestEngine(t)
	rec := do(t, e, http.MethodPost, "/v1/chat/completions", "", map[string]any{"model": "x"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token 期望 401, 实际 %d", rec.Code)
	}
	assertOpenAIError(t, rec, "unauthorized")
}

// ===== S3 前置门禁（#25）=====

// withLLMNoSub 指向桩并令占位订阅检查判「无有效订阅」。
func withLLMNoSub(url string) func(*config.Configuration) {
	return func(cfg *config.Configuration) {
		cfg.LLM.BaseURL = url
		cfg.LLM.StubNoSubscription = true
	}
}

// withLLMMaxBytes 指向桩并设请求体上限，便于 413 边界测试（避免造 25MB 大 body）。
func withLLMMaxBytes(url string, max int64) func(*config.Configuration) {
	return func(cfg *config.Configuration) {
		cfg.LLM.BaseURL = url
		cfg.LLM.MaxRequestBytes = max
	}
}

// stubChatJSON 返回非流式 JSON 200 的桩 litellm，并记录命中次数（验证门禁是否拦在转发前）。
func stubChatJSON(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"c1","usage":{"total_tokens":3}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// 无活跃订阅 → 402 no_active_subscription，且请求不转发到 litellm（订阅先于转发）。
func TestChatCompletions_NoSubscription402NotForwarded(t *testing.T) {
	srv, hits := stubChatJSON(t)
	e := newTestEngine(t, withLLMNoSub(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": true,
	})
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("无订阅期望 402, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "no_active_subscription")
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("无订阅不应转发到 litellm, 实际命中 %d 次", n)
	}
}

// 请求体 >上限 → 413 request_too_large，且不转发。
func TestChatCompletions_RequestTooLarge413(t *testing.T) {
	srv, hits := stubChatJSON(t)
	bodyMap := map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hello world"}}, "stream": false,
	}
	raw, _ := json.Marshal(bodyMap)
	e := newTestEngine(t, withLLMMaxBytes(srv.URL, int64(len(raw))-1)) // 上限比实际小 1 字节
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, bodyMap)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限期望 413, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "request_too_large")
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("超限不应转发, 实际命中 %d", n)
	}
}

// 恰好等于上限 → 放行（边界：25MB 含义为 <=上限放行、>上限拒）。
func TestChatCompletions_ExactlyAtLimitAllowed(t *testing.T) {
	srv, hits := stubChatJSON(t)
	bodyMap := map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hello world"}}, "stream": false,
	}
	raw, _ := json.Marshal(bodyMap)
	e := newTestEngine(t, withLLMMaxBytes(srv.URL, int64(len(raw)))) // 恰好等于实际体积
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, bodyMap)
	if rec.Code != http.StatusOK {
		t.Fatalf("恰好达上限应放行(200), 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("恰好达上限应转发一次, 实际命中 %d", n)
	}
}

// 顺序契约：无订阅 + 超大请求同时触发 → 402 优先（订阅先于体积）。
func TestChatCompletions_SubscriptionBeatsTooLarge(t *testing.T) {
	srv, hits := stubChatJSON(t)
	bodyMap := map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hello world"}},
	}
	raw, _ := json.Marshal(bodyMap)
	e := newTestEngine(t, func(cfg *config.Configuration) {
		cfg.LLM.BaseURL = srv.URL
		cfg.LLM.StubNoSubscription = true             // 无订阅
		cfg.LLM.MaxRequestBytes = int64(len(raw)) - 1 // 且超限
	})
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, bodyMap)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("订阅应先于体积, 期望 402, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "no_active_subscription")
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("门禁拦截不应转发, 实际命中 %d", n)
	}
}
