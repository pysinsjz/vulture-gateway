package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// 缺省值（config 未配时回退）。
const (
	defaultStreamIdleTimeout    = 120 * time.Second // chunk 间空闲上限（ADR-0008 / #24）
	defaultStreamRequestTimeout = 30 * time.Minute  // 单请求总时长上限（ADR-0008 / #24）
	defaultMaxRequestBytes      = 25 * 1024 * 1024  // chat 请求体上限 25MB（#25）
)

// LLMHandler 实现 LLM 代理域（/v1/*，OpenAI 兼容，#23 起）。
// 鉴权由 JWTAuthLLM 完成；错误体全线 OpenAI 形态 {error:{message,type,code}}（#15 基座）。
type LLMHandler struct {
	svc             *service.LLMService
	sub             service.SubscriptionChecker
	meter           *service.MeteringService
	idleTimeout     time.Duration // chunk 间空闲上限
	requestTimeout  time.Duration // 单请求总时长上限
	maxRequestBytes int64         // chat 请求体上限
}

// NewLLMHandler 构造 handler。超时/上限来自 LLMConfig，<=0 时回退缺省（120s/30m/25MB）。
func NewLLMHandler(svc *service.LLMService, sub service.SubscriptionChecker, meter *service.MeteringService, idleTimeout, requestTimeout time.Duration, maxRequestBytes int64) *LLMHandler {
	if idleTimeout <= 0 {
		idleTimeout = defaultStreamIdleTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = defaultStreamRequestTimeout
	}
	if maxRequestBytes <= 0 {
		maxRequestBytes = defaultMaxRequestBytes
	}
	return &LLMHandler{svc: svc, sub: sub, meter: meter, idleTimeout: idleTimeout, requestTimeout: requestTimeout, maxRequestBytes: maxRequestBytes}
}

// ListModels 代理 litellm 模型列表，脱敏后透传上游状态/体（D1，#23）。
//
//	GET /v1/models  (Bearer)
func (h *LLMHandler) ListModels(c *gin.Context) {
	userUUID := c.GetString(middleware.CtxKeySub)
	res, err := h.svc.ListModels(c.Request.Context(), userUUID)
	if err != nil {
		// litellm 不可达：网关自身错误也用 OpenAI 形态（503/上游不可用）。
		apierror.AbortOpenAI(c, http.StatusBadGateway, apierror.OpenAITypeInvalidRequest, "upstream_unavailable", "模型服务暂时不可用")
		return
	}

	// 脱敏：剥成本敏感头 + 逐跳头，保留 x-litellm-call-id 等；状态/体原样透传（含上游错误体）。
	litellm.CopySafeHeaders(c.Writer.Header(), res.Header)
	c.Status(res.Status)
	_, _ = c.Writer.Write(res.Body)
}

// ChatCompletions 代理 litellm 推理（D2，#24）：流式 SSE 逐 chunk 透传 + include_usage 注入 + 双超时。
//
//	POST /v1/chat/completions  (Bearer)
//
// 前置门禁顺序（#25，固化处理顺序契约）：鉴权(中间件) → 订阅检查(402) → 请求体上限(413) →
// 窗口预检(429, #26) → 转发。无订阅 / 超大请求绝不转发到 litellm。窗口预检在 #26 接入，置于此后。
func (h *LLMHandler) ChatCompletions(c *gin.Context) {
	// 门禁 1：订阅检查（402）。先于体积与转发——账号级总闸，无需读 body。
	userUUID := c.GetString(middleware.CtxKeySub)
	active, err := h.sub.HasActiveSubscription(c.Request.Context(), userUUID)
	if err != nil {
		apierror.AbortOpenAI(c, http.StatusBadGateway, apierror.OpenAITypeInvalidRequest, "subscription_check_failed", "订阅状态暂不可用")
		return
	}
	if !active {
		apierror.AbortOpenAI(c, http.StatusPaymentRequired, apierror.OpenAITypeSubscriptionError, "no_active_subscription", "No active subscription. Subscribe to a plan to use the model.")
		return
	}

	// 门禁 2：请求体上限（413）。先按 Content-Length 快判，再以 MaxBytesReader 兜底（防缺失/伪造 Content-Length）。
	if c.Request.ContentLength > h.maxRequestBytes {
		h.abortRequestTooLarge(c)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, h.maxRequestBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.abortRequestTooLarge(c)
			return
		}
		apierror.AbortOpenAI(c, http.StatusBadRequest, apierror.OpenAITypeInvalidRequest, "invalid_request_error", "无法读取请求体")
		return
	}

	// 门禁 3：窗口预检（429，乐观放行）。任一窗已触顶即拒，附恢复头。Redis 抖动时失败放行（不阻断付费用户）。
	if pre, perr := h.meter.Precheck(c.Request.Context(), userUUID, time.Now()); perr == nil && pre.Exceeded {
		writeWindowExceeded(c, pre)
		return
	}

	// 总时长上限：绑定到请求 ctx，连接建立与读取整体受 30min 约束；空闲在 PumpStream 内治理。
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.requestTimeout)
	defer cancel()

	res, err := h.forwardChat(ctx, userUUID, body)
	if err != nil {
		apierror.AbortOpenAI(c, http.StatusBadGateway, apierror.OpenAITypeInvalidRequest, "upstream_unavailable", "模型服务暂时不可用")
		return
	}
	defer func() { _ = res.Body.Close() }()

	// 脱敏头：剥成本敏感 + 逐跳，保留 x-litellm-call-id。
	litellm.CopySafeHeaders(c.Writer.Header(), res.Header)

	// 上游错误（非 200）：原样透传，零计费（硬错误不扣，ADR-0008）。
	if res.Status != http.StatusOK {
		c.Status(res.Status)
		_, _ = io.Copy(c.Writer, res.Body)
		return
	}

	// 非流式 200 JSON：缓冲透传后按响应体 usage 计量（缺失则估算兜底）。
	if !isEventStream(res.Header) {
		respBody, _ := io.ReadAll(res.Body)
		c.Status(http.StatusOK)
		_, _ = c.Writer.Write(respBody)
		usage, completionChars := litellm.UsageFromJSON(respBody)
		h.recordUsage(userUUID, body, usage, completionChars)
		return
	}

	// 流式 SSE：经 SSESniffer 旁路取 usage，落 200 + 头，逐 chunk flush 透传，双超时治理。
	c.Status(http.StatusOK)
	flusher, _ := c.Writer.(http.Flusher)
	var flush func()
	if flusher != nil {
		flush = flusher.Flush
	}
	sniffer := litellm.NewSSESniffer(c.Writer)
	// 超时/断流：已写部分即止（头已发，无法改写状态）；按已生成部分计费（usage 缺失则估算）。
	_ = litellm.PumpStream(ctx, sniffer, flush, res.Body, h.idleTimeout)
	h.recordUsage(userUUID, body, sniffer.Usage(), sniffer.CompletionChars())
}

// forwardChat 转发 chat 请求并做一次性自愈轮换（ADR-0014 失败处理 ②）：
// 上游返 401/403（库里 key 被 litellm 拒，如手工删 key）→ 轮换重签 + 用新 key 重试一次（仅一次防死循环）。
// 此时流式响应体尚未开写（handler 后续才泵流），无部分写入风险。轮换失败则原样返回 401/403 让上层透传。
func (h *LLMHandler) forwardChat(ctx context.Context, userUUID string, body []byte) (*litellm.ChatResponse, error) {
	res, err := h.svc.ChatCompletions(ctx, userUUID, body)
	if err != nil {
		return nil, err
	}
	if res.Status != http.StatusUnauthorized && res.Status != http.StatusForbidden {
		return res, nil
	}
	if healErr := h.svc.RegenerateVirtualKey(ctx, userUUID); healErr != nil {
		return res, nil // 轮换失败：原样返回，上层透传上游错误体
	}
	_ = res.Body.Close() // 轮换成功：丢弃旧响应体，用新 key 重试一次
	retry, err := h.svc.ChatCompletions(ctx, userUUID, body)
	if err != nil {
		return nil, err
	}
	return retry, nil
}

// recordUsage 在转发结束后扣减用量：优先用上游 usage，缺失时按 prompt/输出字符数估算兜底（#26）。
// best-effort：响应已发，扣减失败仅记账丢失、不影响客户端。用独立 ctx，确保客户端断开仍能落账。
func (h *LLMHandler) recordUsage(userUUID string, reqBody []byte, usage *litellm.Usage, completionChars int) {
	u := usage
	if u == nil {
		est := service.EstimateUsage(service.PromptChars(reqBody), completionChars)
		u = &est
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.meter.Record(ctx, userUUID, *u, time.Now())
}

// writeWindowExceeded 写入 429 + 恢复头（Retry-After / X-Window-*-Reset，仅触顶窗出现，llm-proxy.md §4）。
func writeWindowExceeded(c *gin.Context, pre *service.PrecheckResult) {
	c.Header("Retry-After", strconv.FormatInt(pre.RetryAfter, 10))
	for _, r := range pre.Resets {
		switch r.Window {
		case service.Window5h:
			c.Header("X-Window-5h-Reset", strconv.FormatInt(r.ResetUnix, 10))
		case service.WindowWeek:
			c.Header("X-Window-Week-Reset", strconv.FormatInt(r.ResetUnix, 10))
		}
	}
	apierror.AbortOpenAI(c, http.StatusTooManyRequests, apierror.OpenAITypeRateLimit, "usage_window_exceeded", "Usage window cap reached.")
}

// abortRequestTooLarge 写入 413 OpenAI 错误体（请求体超上限，llm-proxy.md §5 / #25）。
func (h *LLMHandler) abortRequestTooLarge(c *gin.Context) {
	apierror.AbortOpenAI(c, http.StatusRequestEntityTooLarge, apierror.OpenAITypeInvalidRequest, "request_too_large", "请求体超过上限")
}

// isEventStream 判定上游响应是否为 SSE 流（Content-Type: text/event-stream）。
func isEventStream(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/event-stream")
}
