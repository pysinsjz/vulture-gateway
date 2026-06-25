package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

// VirtualKeyResolver 抽象按用户解析/轮换 litellm virtual key（ADR-0014）。*VirtualKeyService 满足；接口化以便单测。
type VirtualKeyResolver interface {
	GetOrCreateVirtualKey(ctx context.Context, userUUID string) (string, error)
	RevokeAndRegenerate(ctx context.Context, userUUID string) (string, error)
}

// LLMService 是 LLM 代理域的服务层（#23 起）。ADR-0014：key 解析收敛在此——按 userUUID get-or-create
// 用户专属 virtual key 后注入 Proxy Client 转发。订阅门禁（#25）、窗口计量（#26）逻辑一行不改。
type LLMService struct {
	llm   litellm.Client
	vkeys VirtualKeyResolver
}

// NewLLMService 构造服务。
func NewLLMService(llm litellm.Client, vkeys VirtualKeyResolver) *LLMService {
	return &LLMService{llm: llm, vkeys: vkeys}
}

// ListModels 代理 litellm 模型列表，注入用户 virtual key（ADR-0014：/v1/models 同样走用户 key）。
func (s *LLMService) ListModels(ctx context.Context, userUUID string) (*litellm.ProxyResult, error) {
	key, err := s.vkeys.GetOrCreateVirtualKey(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	return s.llm.ListModels(ctx, key)
}

// ChatCompletions 代理 litellm 推理：先 get-or-create 用户 virtual key，再对流式请求强制注入
// stream_options.include_usage=true（#24），转发并返回活体响应。请求体非法 JSON 时原样转发，让 litellm 返标准 400。
func (s *LLMService) ChatCompletions(ctx context.Context, userUUID string, body []byte) (*litellm.ChatResponse, error) {
	key, err := s.vkeys.GetOrCreateVirtualKey(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	injected, _, err := litellm.InjectIncludeUsage(body)
	if err != nil {
		injected = body
	}
	return s.llm.ChatCompletions(ctx, key, injected)
}

// RegenerateVirtualKey 触发一次性自愈轮换（ADR-0014 失败处理 ②）：handler 在上游 401/403 分支调用，
// 随后用同一 userUUID 重试 ChatCompletions 即命中新签 key。返回 err 表示轮换失败（放弃重试）。
func (s *LLMService) RegenerateVirtualKey(ctx context.Context, userUUID string) error {
	_, err := s.vkeys.RevokeAndRegenerate(ctx, userUUID)
	return err
}
