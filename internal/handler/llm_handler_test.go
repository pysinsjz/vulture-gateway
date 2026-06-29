package handler_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeProxy 是 litellm.Client 的桩：按调用次序返回预设响应（验证 401→自愈重试）。
type fakeProxy struct {
	calls    int32
	statuses []int
	bodies   []string
	gotKeys  []string
}

func (f *fakeProxy) ListModels(_ context.Context, key string) (*litellm.ProxyResult, error) {
	return &litellm.ProxyResult{Status: http.StatusOK, Header: http.Header{}, Body: []byte(`{}`)}, nil
}

// ImageGenerations 桩：固定返回 200 JSON；图片自愈路径由 router 层用真 httptest 覆盖。
func (f *fakeProxy) ImageGenerations(_ context.Context, _ string, _ []byte) (*litellm.ProxyResult, error) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &litellm.ProxyResult{Status: http.StatusOK, Header: h, Body: []byte(`{"data":[]}`)}, nil
}

// QianwenMultimodalGeneration 桩：固定返回 200 JSON；千问透传端点的具体行为由 router 层用真 httptest 覆盖。
func (f *fakeProxy) QianwenMultimodalGeneration(_ context.Context, _ string, _ []byte) (*litellm.ProxyResult, error) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &litellm.ProxyResult{Status: http.StatusOK, Header: h, Body: []byte(`{"output":{"choices":[]}}`)}, nil
}

func (f *fakeProxy) ChatCompletions(_ context.Context, key string, _ []byte) (*litellm.ChatResponse, error) {
	i := int(atomic.AddInt32(&f.calls, 1)) - 1
	f.gotKeys = append(f.gotKeys, key)
	status := http.StatusOK
	body := `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	if i < len(f.statuses) {
		status = f.statuses[i]
	}
	if i < len(f.bodies) {
		body = f.bodies[i]
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &litellm.ChatResponse{Status: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}, nil
}

// fakeResolver 是 VirtualKeyResolver 桩：记录轮换次数，按次序给出 key。
type fakeResolver struct {
	keys       []string
	idx        int32
	regenCalls int32
	regenFails bool
}

func (r *fakeResolver) GetOrCreateVirtualKey(_ context.Context, _ string) (string, error) {
	i := int(atomic.AddInt32(&r.idx, 1)) - 1
	if i < len(r.keys) {
		return r.keys[i], nil
	}
	return "sk-default", nil
}

func (r *fakeResolver) RevokeAndRegenerate(_ context.Context, _ string) (string, error) {
	atomic.AddInt32(&r.regenCalls, 1)
	if r.regenFails {
		return "", context.DeadlineExceeded
	}
	return "sk-fresh", nil
}

func newLLMHandlerFixture(t *testing.T, proxy litellm.Client, resolver service.VirtualKeyResolver) *gin.Engine {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	svc := service.NewLLMService(proxy, resolver)
	sub := service.NewStubSubscriptionChecker(true) // 有有效订阅，放行门禁
	meter := service.NewMeteringService(rdb, []service.UsageWindow{
		{Name: service.Window5h, Size: service.Window5hSize, Cap: 0}, // Cap=0 不限，预检放行
	}, service.Pricing{PromptCreditPerToken: 1, CompletionCreditPerToken: 1})
	h := handler.NewLLMHandler(svc, sub, meter, 0, 0, 0)

	gin.SetMode(gin.TestMode)
	e := gin.New()
	e.Use(func(c *gin.Context) { c.Set(middleware.CtxKeySub, "u1") })
	e.POST("/v1/chat/completions", h.ChatCompletions)
	return e
}

func postChat(t *testing.T, e *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// 上游首发 401 → 自愈轮换 + 用新 key 重试一次 → 第二次 200 透传。
func TestChatSelfHeal_RetriesOnceWithFreshKey(t *testing.T) {
	proxy := &fakeProxy{statuses: []int{http.StatusUnauthorized, http.StatusOK}}
	resolver := &fakeResolver{keys: []string{"sk-stale", "sk-fresh"}}
	e := newLLMHandlerFixture(t, proxy, resolver)

	rec := postChat(t, e)

	if rec.Code != http.StatusOK {
		t.Fatalf("自愈后应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&resolver.regenCalls) != 1 {
		t.Errorf("应轮换一次, 实际 %d", resolver.regenCalls)
	}
	if atomic.LoadInt32(&proxy.calls) != 2 {
		t.Errorf("应转发两次（首发+重试）, 实际 %d", proxy.calls)
	}
	// 第二次转发应用轮换后的新 key。
	if len(proxy.gotKeys) == 2 && proxy.gotKeys[1] != "sk-fresh" {
		t.Errorf("重试应用新 key sk-fresh, 实际 %q", proxy.gotKeys[1])
	}
}

// 轮换失败 → 不重试，原样透传上游 401。
func TestChatSelfHeal_RegenFailsPassesThrough(t *testing.T) {
	proxy := &fakeProxy{statuses: []int{http.StatusForbidden}}
	resolver := &fakeResolver{keys: []string{"sk-stale"}, regenFails: true}
	e := newLLMHandlerFixture(t, proxy, resolver)

	rec := postChat(t, e)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("轮换失败应原样透传 403, 实际 %d", rec.Code)
	}
	if atomic.LoadInt32(&proxy.calls) != 1 {
		t.Errorf("轮换失败不应重试, 转发次数=%d", proxy.calls)
	}
}

// 上游直接 200 → 不触发自愈。
func TestChatSelfHeal_NoHealOn200(t *testing.T) {
	proxy := &fakeProxy{statuses: []int{http.StatusOK}}
	resolver := &fakeResolver{keys: []string{"sk-ok"}}
	e := newLLMHandlerFixture(t, proxy, resolver)

	rec := postChat(t, e)

	if rec.Code != http.StatusOK {
		t.Fatalf("应 200, 实际 %d", rec.Code)
	}
	if atomic.LoadInt32(&resolver.regenCalls) != 0 {
		t.Errorf("200 不应轮换, 实际 %d", resolver.regenCalls)
	}
}
