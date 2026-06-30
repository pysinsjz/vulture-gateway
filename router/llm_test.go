package router_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/config"
)

func withLLM(url string) func(*config.Configuration) {
	return func(cfg *config.Configuration) { cfg.LLM.BaseURL = url }
}

// newLLMEngine 装配引擎并预置测试主体（user-llm / u）的 virtual key 缓存为 "test-vkey"（ADR-0014）。
// router 测试无 postgres：LLM 转发路径靠缓存命中取 key，免触 DB；签发/落库/自愈轮换由 VirtualKeyService 单测覆盖。
// 转发的桩 litellm 断言收到 Authorization=Bearer test-vkey，即验证「网关按用户注入专属 key」。
func newLLMEngine(t *testing.T, opts ...func(*config.Configuration)) *gin.Engine {
	t.Helper()
	e, mr := newTestEngineWithRedis(t, opts...)
	for _, sub := range []string{"user-llm", "u"} {
		if err := mr.Set("vkey:"+sub, "test-vkey"); err != nil {
			t.Fatalf("预置 vkey 缓存失败: %v", err)
		}
	}
	return e
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
	e := newLLMEngine(t, withLLM(srv.URL))
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
	e := newLLMEngine(t, withLLM(srv.URL))

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
	e := newLLMEngine(t, withLLM(srv.URL))
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
	e := newLLMEngine(t, withLLM("http://127.0.0.1:1"))
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

	e := newLLMEngine(t, withLLM(srv.URL))
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

	e := newLLMEngine(t, withLLM(srv.URL))
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

	e := newLLMEngine(t, withLLM(srv.URL))
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

	e := newLLMEngine(t, withLLM(srv.URL))
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

	e := newLLMEngine(t, withLLMIdle(srv.URL, 80*time.Millisecond))
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
		_, _ = w.Write([]byte(`{"id":"c1","usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// 无活跃订阅 → 402 no_active_subscription，且请求不转发到 litellm（订阅先于转发）。
func TestChatCompletions_NoSubscription402NotForwarded(t *testing.T) {
	srv, hits := stubChatJSON(t)
	e := newLLMEngine(t, withLLMNoSub(srv.URL))
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
	e := newLLMEngine(t, withLLMMaxBytes(srv.URL, int64(len(raw))-1)) // 上限比实际小 1 字节
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
	e := newLLMEngine(t, withLLMMaxBytes(srv.URL, int64(len(raw)))) // 恰好等于实际体积
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
	e := newLLMEngine(t, func(cfg *config.Configuration) {
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

// ===== S4 计量与额度强制（#26）=====

// withLLM5hCap 指向桩并设 5h 窗 Credit 上限（周窗不限）。
func withLLM5hCap(url string, cap int64) func(*config.Configuration) {
	return func(cfg *config.Configuration) {
		cfg.LLM.BaseURL = url
		cfg.LLM.Window5hCap = cap
		cfg.LLM.CreditsPerPromptToken = 1
		cfg.LLM.CreditsPerCompletionToken = 1
	}
}

func chatReq() map[string]any {
	return map[string]any{
		"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": false,
	}
}

// 乐观放行 + 触顶 429：首请求扣满 Cap（单请求可超窗），次请求触顶 429 + 恢复头，且不转发。
func TestChatCompletions_WindowExceeded429(t *testing.T) {
	srv, hits := stubChatJSON(t) // 每次 usage=prompt2+completion1 → 3 Credit
	e := newLLMEngine(t, withLLM5hCap(srv.URL, 3))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	// 首请求：空窗乐观放行（即便本次扣 3 = Cap）。
	rec1 := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq())
	if rec1.Code != http.StatusOK {
		t.Fatalf("首请求应放行 200, 实际 %d: %s", rec1.Code, rec1.Body.String())
	}

	// 次请求：已触顶 → 429 usage_window_exceeded + 恢复头，且不再转发。
	rec2 := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq())
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("触顶应 429, 实际 %d: %s", rec2.Code, rec2.Body.String())
	}
	assertOpenAIError(t, rec2, "usage_window_exceeded")
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("429 应带 Retry-After")
	}
	if rec2.Header().Get("X-Window-5h-Reset") == "" {
		t.Error("5h 窗触顶应带 X-Window-5h-Reset")
	}
	if rec2.Header().Get("X-Window-Week-Reset") != "" {
		t.Error("周窗未配额(不限)不应带 X-Window-Week-Reset")
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("触顶请求不应转发, litellm 应仅命中 1 次, 实际 %d", n)
	}
}

// 错误体可区分：网关触顶 code=usage_window_exceeded / type=rate_limit_error（区别于上游透传限流）。
func TestChatCompletions_GatewayRateLimitDistinct(t *testing.T) {
	srv, _ := stubChatJSON(t)
	e := newLLMEngine(t, withLLM5hCap(srv.URL, 3))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")
	_ = do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq()) // 填满
	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq())

	var oe struct {
		Error struct{ Type, Code string } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &oe)
	if oe.Error.Type != "rate_limit_error" || oe.Error.Code != "usage_window_exceeded" {
		t.Errorf("网关触顶应 type=rate_limit_error/code=usage_window_exceeded, 实际 %+v", oe.Error)
	}
}

// usage 缺失 → 估算兜底仍扣费：流式无 usage chunk，估算扣减后次请求触顶。
func TestChatCompletions_MissingUsageEstimatedDebit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		sseWrite(w, fl, "data: {\"choices\":[{\"delta\":{\"content\":\"hello world response\"}}]}\n\n")
		sseWrite(w, fl, "data: [DONE]\n\n") // 无 usage chunk
	}))
	t.Cleanup(srv.Close)

	e := newLLMEngine(t, withLLM5hCap(srv.URL, 1)) // Cap 极小，任何估算扣减都将触顶
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	body := map[string]any{"model": "gpt-4", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": true}
	if rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, body); rec.Code != http.StatusOK {
		t.Fatalf("首请求应放行, 实际 %d", rec.Code)
	}
	// 估算已扣费 → 次请求触顶。
	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("usage 缺失应估算扣费致次请求 429, 实际 %d", rec.Code)
	}
}

// 硬错误零计费：上游 400 不扣费，后续请求不应因「幽灵扣费」触顶。
func TestChatCompletions_HardErrorZeroBill(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"bad","type":"invalid_request_error","code":"x"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"c1","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)

	e := newLLMEngine(t, withLLM5hCap(srv.URL, 1)) // Cap=1：若 400 误扣费，次请求将 429
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	if rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq()); rec.Code != http.StatusBadRequest {
		t.Fatalf("首请求应透传 400, 实际 %d", rec.Code)
	}
	// 400 零计费 → 窗口仍空 → 次请求放行（非 429）。
	rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq())
	if rec.Code != http.StatusOK {
		t.Fatalf("硬错误应零计费, 次请求应放行 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

// 并发原子性：N 并发请求各扣 3 Credit，Cap=N*3 全部放行；第 N+1 次触顶（证明无丢失）。
func TestChatCompletions_ConcurrentDebitsAtomic(t *testing.T) {
	const n = 12
	srv, _ := stubChatJSON(t) // 每次 3 Credit
	e := newLLMEngine(t, withLLM5hCap(srv.URL, n*3))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq()).Code
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("并发第 %d 个应放行 200, 实际 %d", i, code)
		}
	}
	// N 笔扣减全部落账 → 窗满 → 第 N+1 触顶。
	if rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq()); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%d 笔并发扣减后应触顶 429, 实际 %d（疑似丢失扣减）", n, rec.Code)
	}
}

// ===== 图片生成（/v1/images/generations）=====

// stubImages 返回 200 + 标准 OpenAI 图片响应的桩 litellm，并记录命中次数与 Authorization（验证 virtual key 注入）。
func stubImages(t *testing.T) (*httptest.Server, *string, *int32) {
	t.Helper()
	var gotAuth string
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Litellm-Call-Id", "img-call-1")
		w.Header().Set("X-Litellm-Response-Cost", "0.040")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"created":1700000000,"data":[{"url":"https://example.com/a.png"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth, &hits
}

func imageReq() map[string]any {
	return map[string]any{"model": "dall-e-3", "prompt": "a cat on a roof", "n": 1, "size": "1024x1024"}
}

// 正路：200 JSON 透传 + 注入 virtual key + 剥成本头 + 保留 call-id。
func TestImageGenerations_HappyPath(t *testing.T) {
	srv, gotAuth, hits := stubImages(t)
	e := newLLMEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/images/generations", token, imageReq())
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"url":"https://example.com/a.png"`) {
		t.Errorf("响应体应原样透传, 实际 %s", rec.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("litellm 应命中 1 次, 实际 %d", atomic.LoadInt32(hits))
	}
	if *gotAuth != "Bearer test-vkey" {
		t.Errorf("应注入 virtual key, 桩收到 Authorization=%q", *gotAuth)
	}
	if rec.Header().Get("X-Litellm-Call-Id") != "img-call-1" {
		t.Error("x-litellm-call-id 应保留透传")
	}
	if rec.Header().Get("X-Litellm-Response-Cost") != "" {
		t.Error("成本头应被剥除")
	}
}

// 无 Bearer → 401（JWTAuthLLM 同时覆盖 chat 与 images）。
func TestImageGenerations_NoTokenUnauthorized(t *testing.T) {
	e := newTestEngine(t)
	rec := do(t, e, http.MethodPost, "/v1/images/generations", "", imageReq())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token 期望 401, 实际 %d", rec.Code)
	}
	assertOpenAIError(t, rec, "unauthorized")
}

// 无活跃订阅 → 402 no_active_subscription，且不转发到 litellm。
func TestImageGenerations_NoSubscription402NotForwarded(t *testing.T) {
	srv, _, hits := stubImages(t)
	e := newLLMEngine(t, withLLMNoSub(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/images/generations", token, imageReq())
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("无订阅期望 402, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "no_active_subscription")
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("无订阅不应转发, 实际命中 %d", n)
	}
}

// 请求体 >上限 → 413 request_too_large，且不转发。
func TestImageGenerations_RequestTooLarge413(t *testing.T) {
	srv, _, hits := stubImages(t)
	bodyMap := imageReq()
	raw, _ := json.Marshal(bodyMap)
	e := newLLMEngine(t, withLLMMaxBytes(srv.URL, int64(len(raw))-1))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/images/generations", token, bodyMap)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限期望 413, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "request_too_large")
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("超限不应转发, 实际命中 %d", n)
	}
}

// litellm 不可达 → OpenAI 形态 502 upstream_unavailable。
func TestImageGenerations_UpstreamUnreachable(t *testing.T) {
	e := newLLMEngine(t, withLLM("http://127.0.0.1:1"))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodPost, "/v1/images/generations", token, imageReq())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "")
}

// 上游错误：litellm 返 400 → 网关原样透传状态码与体。
func TestImageGenerations_UpstreamErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad size","type":"invalid_request_error","code":"size_not_supported"}}`))
	}))
	t.Cleanup(srv.Close)

	e := newLLMEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := do(t, e, http.MethodPost, "/v1/images/generations", token, imageReq())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("应透传上游 400, 实际 %d", rec.Code)
	}
	assertOpenAIError(t, rec, "size_not_supported")
}

// 跨端点窗口共享：chat 把 5h 窗打满 → 后续 images 也被同窗预检拦截 429。
func TestImageGenerations_WindowExceededByChat429(t *testing.T) {
	// chat 与 images 共用同一个 litellm 桩：chat 路径产生 usage→扣 Credit 填满窗口。
	srv, _ := stubChatJSON(t) // 每次 usage=prompt2+completion1 → 3 Credit
	e := newLLMEngine(t, withLLM5hCap(srv.URL, 3))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	// 一发 chat 把窗口填满（Cap=3，乐观放行扣满）。
	if rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq()); rec.Code != http.StatusOK {
		t.Fatalf("首发 chat 应放行 200, 实际 %d", rec.Code)
	}

	// images 触顶 → 429 usage_window_exceeded（同窗口共享，跨端点生效）。
	rec := do(t, e, http.MethodPost, "/v1/images/generations", token, imageReq())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("窗口已满 images 应 429, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "usage_window_exceeded")
}

// ===== 图片编辑（/v1/images/edits）=====

// buildImageEditsBody 构造一个最小可用的 multipart/form-data 请求体，包含 image/prompt/model/size 等字段。
// 返回 body 字节与 Content-Type（含 boundary）——后者必须随请求头一同发出，否则上游无法解多部分。
func buildImageEditsBody(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	imagePart, err := mw.CreateFormFile("image", "input.png")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := imagePart.Write([]byte("\x89PNG\r\n\x1a\nfake-png-bytes")); err != nil {
		t.Fatalf("write image: %v", err)
	}
	for k, v := range map[string]string{
		"prompt": "make it look like a painting",
		"model":  "gpt-image-1",
		"n":      "1",
		"size":   "1024x1024",
	} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

// doRaw 走与 do() 同口径的请求构造，但允许传入原始 body 与自定义 Content-Type（multipart 等非 JSON 场景）。
func doRaw(t *testing.T, e *gin.Engine, method, path, bearer, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// stubImageEdits 返回 200 + 标准 OpenAI 图片响应的桩 litellm，记录命中次数、Authorization、Content-Type 与回放 body
// 长度（验证 multipart 边界透传）。
type stubImageEditsCapture struct {
	hits         int32
	gotAuth      string
	gotCT        string
	gotBodyBytes int
	gotPath      string
}

func stubImageEdits(t *testing.T) (*httptest.Server, *stubImageEditsCapture) {
	t.Helper()
	cap := &stubImageEditsCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&cap.hits, 1)
		cap.gotAuth = r.Header.Get("Authorization")
		cap.gotCT = r.Header.Get("Content-Type")
		cap.gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		cap.gotBodyBytes = len(raw)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Litellm-Call-Id", "edits-call-1")
		w.Header().Set("X-Litellm-Response-Cost", "0.080")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"created":1700000001,"data":[{"url":"https://example.com/edit.png"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// 正路：multipart body 200 JSON 透传 + 注入 virtual key + 剥成本头 + 保留 call-id + Content-Type/boundary 原样传给 litellm。
func TestImageEdits_HappyPath(t *testing.T) {
	srv, cap := stubImageEdits(t)
	e := newLLMEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")
	body, ct := buildImageEditsBody(t)

	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", token, ct, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"url":"https://example.com/edit.png"`) {
		t.Errorf("响应体应原样透传, 实际 %s", rec.Body.String())
	}
	if atomic.LoadInt32(&cap.hits) != 1 {
		t.Errorf("litellm 应命中 1 次, 实际 %d", atomic.LoadInt32(&cap.hits))
	}
	if cap.gotPath != "/v1/images/edits" {
		t.Errorf("上游路径应为 /v1/images/edits, 实际 %q", cap.gotPath)
	}
	if cap.gotAuth != "Bearer test-vkey" {
		t.Errorf("应注入 virtual key, 桩收到 Authorization=%q", cap.gotAuth)
	}
	// multipart Content-Type（含 boundary）必须原样传——否则上游无法解多部分。
	if !strings.HasPrefix(cap.gotCT, "multipart/form-data") || !strings.Contains(cap.gotCT, "boundary=") {
		t.Errorf("Content-Type 应为 multipart/form-data; boundary=..., 实际 %q", cap.gotCT)
	}
	if cap.gotBodyBytes != len(body) {
		t.Errorf("body 应原样转发(%d B), 上游收到 %d B", len(body), cap.gotBodyBytes)
	}
	if rec.Header().Get("X-Litellm-Call-Id") != "edits-call-1" {
		t.Error("x-litellm-call-id 应保留透传")
	}
	if rec.Header().Get("X-Litellm-Response-Cost") != "" {
		t.Error("成本头应被剥除")
	}
}

// 无 Bearer → 401（JWTAuthLLM 同时覆盖 chat/images/edits）。
func TestImageEdits_NoTokenUnauthorized(t *testing.T) {
	e := newTestEngine(t)
	body, ct := buildImageEditsBody(t)
	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", "", ct, body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token 期望 401, 实际 %d", rec.Code)
	}
	assertOpenAIError(t, rec, "unauthorized")
}

// 无活跃订阅 → 402 no_active_subscription，且不转发到 litellm。
func TestImageEdits_NoSubscription402NotForwarded(t *testing.T) {
	srv, cap := stubImageEdits(t)
	e := newLLMEngine(t, withLLMNoSub(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")
	body, ct := buildImageEditsBody(t)

	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", token, ct, body)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("无订阅期望 402, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "no_active_subscription")
	if n := atomic.LoadInt32(&cap.hits); n != 0 {
		t.Errorf("无订阅不应转发, 实际命中 %d", n)
	}
}

// 请求体 >上限 → 413 request_too_large，且不转发。
func TestImageEdits_RequestTooLarge413(t *testing.T) {
	srv, cap := stubImageEdits(t)
	body, ct := buildImageEditsBody(t)
	e := newLLMEngine(t, withLLMMaxBytes(srv.URL, int64(len(body))-1))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", token, ct, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限期望 413, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "request_too_large")
	if n := atomic.LoadInt32(&cap.hits); n != 0 {
		t.Errorf("超限不应转发, 实际命中 %d", n)
	}
}

// litellm 不可达 → OpenAI 形态 502 upstream_unavailable。
func TestImageEdits_UpstreamUnreachable(t *testing.T) {
	e := newLLMEngine(t, withLLM("http://127.0.0.1:1"))
	token := issueViaScaffold(t, e, "u", "d")
	body, ct := buildImageEditsBody(t)

	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", token, ct, body)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "")
}

// 上游错误：litellm 返 400 → 网关原样透传状态码与体。
func TestImageEdits_UpstreamErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"unsupported size","type":"invalid_request_error","code":"size_not_supported"}}`))
	}))
	t.Cleanup(srv.Close)

	e := newLLMEngine(t, withLLM(srv.URL))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")
	body, ct := buildImageEditsBody(t)

	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", token, ct, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("应透传上游 400, 实际 %d", rec.Code)
	}
	assertOpenAIError(t, rec, "size_not_supported")
}

// 跨端点窗口共享：chat 把 5h 窗打满 → 后续 images/edits 也被同窗预检拦截 429。
func TestImageEdits_WindowExceededByChat429(t *testing.T) {
	srv, _ := stubChatJSON(t) // 每次 usage=prompt2+completion1 → 3 Credit
	e := newLLMEngine(t, withLLM5hCap(srv.URL, 3))
	token := issueViaScaffold(t, e, "user-llm", "dev-llm")

	if rec := do(t, e, http.MethodPost, "/v1/chat/completions", token, chatReq()); rec.Code != http.StatusOK {
		t.Fatalf("首发 chat 应放行 200, 实际 %d", rec.Code)
	}

	body, ct := buildImageEditsBody(t)
	rec := doRaw(t, e, http.MethodPost, "/v1/images/edits", token, ct, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("窗口已满 image edits 应 429, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOpenAIError(t, rec, "usage_window_exceeded")
}
