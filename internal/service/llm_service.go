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

// ChatCompletions 代理 litellm 推理：先对流式请求强制注入 stream_options.include_usage=true（#24），
// 再转发并返回活体响应（流式泵/缓冲在 handler 层做）。请求体非法 JSON 时原样转发，让 litellm 返标准 400。
func (s *LLMService) ChatCompletions(ctx context.Context, body []byte) (*litellm.ChatResponse, error) {
	injected, _, err := litellm.InjectIncludeUsage(body)
	if err != nil {
		injected = body
	}
	return s.llm.ChatCompletions(ctx, injected)
}
