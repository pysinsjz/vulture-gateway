package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

// LLMService 是 LLM 代理域的服务层（#23 起）。当前为 litellm 薄转发；
// 订阅门禁（#25）、窗口计量（#26）等后续切片在此扩展。
type LLMService struct {
	llm litellm.Client
}

// NewLLMService 构造服务。
func NewLLMService(llm litellm.Client) *LLMService {
	return &LLMService{llm: llm}
}

// ListModels 代理 litellm 模型列表，返回上游原始响应（脱敏在 handler 层做）。
func (s *LLMService) ListModels(ctx context.Context) (*litellm.ProxyResult, error) {
	return s.llm.ListModels(ctx)
}
