package handler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// 流式双超时缺省值（config 未配时回退，ADR-0008 / #24）。
const (
	defaultStreamIdleTimeout    = 120 * time.Second
	defaultStreamRequestTimeout = 30 * time.Minute
)

// LLMHandler 实现 LLM 代理域（/v1/*，OpenAI 兼容，#23 起）。
// 鉴权由 JWTAuthLLM 完成；错误体全线 OpenAI 形态 {error:{message,type,code}}（#15 基座）。
type LLMHandler struct {
	svc            *service.LLMService
	idleTimeout    time.Duration // chunk 间空闲上限
	requestTimeout time.Duration // 单请求总时长上限
}

// NewLLMHandler 构造 handler。idle/request 超时来自 LLMConfig，<=0 时回退缺省（120s/30m）。
func NewLLMHandler(svc *service.LLMService, idleTimeout, requestTimeout time.Duration) *LLMHandler {
	if idleTimeout <= 0 {
		idleTimeout = defaultStreamIdleTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = defaultStreamRequestTimeout
	}
	return &LLMHandler{svc: svc, idleTimeout: idleTimeout, requestTimeout: requestTimeout}
}

// ListModels 代理 litellm 模型列表，脱敏后透传上游状态/体（D1，#23）。
//
//	GET /v1/models  (Bearer)
func (h *LLMHandler) ListModels(c *gin.Context) {
	res, err := h.svc.ListModels(c.Request.Context())
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
// 乐观放行（默认通过）；订阅门禁(402)/限额(429)/请求体上限(413)属 #25/#26，本切片不做。
func (h *LLMHandler) ChatCompletions(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		apierror.AbortOpenAI(c, http.StatusBadRequest, apierror.OpenAITypeInvalidRequest, "invalid_request_error", "无法读取请求体")
		return
	}

	// 总时长上限：绑定到请求 ctx，连接建立与读取整体受 30min 约束；空闲在 PumpStream 内治理。
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.requestTimeout)
	defer cancel()

	res, err := h.svc.ChatCompletions(ctx, body)
	if err != nil {
		apierror.AbortOpenAI(c, http.StatusBadGateway, apierror.OpenAITypeInvalidRequest, "upstream_unavailable", "模型服务暂时不可用")
		return
	}
	defer func() { _ = res.Body.Close() }()

	// 脱敏头：剥成本敏感 + 逐跳，保留 x-litellm-call-id。
	litellm.CopySafeHeaders(c.Writer.Header(), res.Header)

	// 非 200（litellm 错误体，OpenAI 形态）或非流式 JSON：缓冲拷贝透传，不做 SSE 泵。
	if res.Status != http.StatusOK || !isEventStream(res.Header) {
		c.Status(res.Status)
		_, _ = io.Copy(c.Writer, res.Body)
		return
	}

	// 流式 SSE：落 200 + 头，逐 chunk flush 透传，双超时治理。
	c.Status(http.StatusOK)
	flusher, _ := c.Writer.(http.Flusher)
	var flush func()
	if flusher != nil {
		flush = flusher.Flush
	}
	// 超时/断流：已写部分即止（头已发，无法改写状态）；按已生成部分计费属 #26。
	_ = litellm.PumpStream(ctx, c.Writer, flush, res.Body, h.idleTimeout)
}

// isEventStream 判定上游响应是否为 SSE 流（Content-Type: text/event-stream）。
func isEventStream(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/event-stream")
}
