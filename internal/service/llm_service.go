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

// ImageGenerations 代理 litellm 图片生成：解析用户 virtual key 后透传请求体。
// 图片接口不存在 stream_options 概念，body 直接转发——非法 JSON 也照转，由 litellm 返标准 400。
func (s *LLMService) ImageGenerations(ctx context.Context, userUUID string, body []byte) (*litellm.ProxyResult, error) {
	key, err := s.vkeys.GetOrCreateVirtualKey(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	return s.llm.ImageGenerations(ctx, key, body)
}

// ImageEdits 代理 litellm 图片编辑：解析用户 virtual key 后透传 multipart 请求体与 Content-Type。
// edits 走 multipart/form-data（图片 + mask + prompt 等），必须把上游 Content-Type（含 boundary）
// 原样传给 litellm.Client，body 直接转发——非法 multipart 也照转，由 litellm 返标准 400。
func (s *LLMService) ImageEdits(ctx context.Context, userUUID string, body []byte, contentType string) (*litellm.ProxyResult, error) {
	key, err := s.vkeys.GetOrCreateVirtualKey(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	return s.llm.ImageEdits(ctx, key, body, contentType)
}

// QianwenMultimodalGeneration 代理 litellm DashScope 透传端点（qwen-image-2.0 等）：
// 解析用户 virtual key 后透传请求体，body 为千问原生形态（input.messages + parameters）。
// 非法 JSON 同样直接转发，由 litellm 返标准 400。
func (s *LLMService) QianwenMultimodalGeneration(ctx context.Context, userUUID string, body []byte) (*litellm.ProxyResult, error) {
	key, err := s.vkeys.GetOrCreateVirtualKey(ctx, userUUID)
	if err != nil {
		return nil, err
	}
	return s.llm.QianwenMultimodalGeneration(ctx, key, body)
}
