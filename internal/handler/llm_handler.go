package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// LLMHandler 实现 LLM 代理域（/v1/*，OpenAI 兼容，#23 起）。
// 鉴权由 JWTAuthLLM 完成；错误体全线 OpenAI 形态 {error:{message,type,code}}（#15 基座）。
type LLMHandler struct {
	svc *service.LLMService
}

// NewLLMHandler 构造 handler。
func NewLLMHandler(svc *service.LLMService) *LLMHandler {
	return &LLMHandler{svc: svc}
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
