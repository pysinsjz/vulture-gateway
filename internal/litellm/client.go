// Package litellm 是网关到 litellm proxy 的 LLM 代理客户端（ADR-0005）。
//
// 网关对桌面端暴露 OpenAI 兼容 /v1/* 端点，自身只做「鉴权 + 转发 litellm + 脱敏」薄层。
// 网关持有 litellm virtual key，转发时注入 Authorization，桌面端永远拿不到（docs/flows/llm-proxy.md）。
//
// Client 为接口，便于 service/handler 用 fake 单测；真实实现 httpClient 注入 *http.Client，
// 契约测试用 httptest 桩 litellm 驱动。
package litellm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client 抽象 litellm 代理契约。随 LLM 域切片（#23 models → #24 chat 流式）逐步扩展。
//
// ADR-0014：去掉构造期单 key，改为每次调用注入「按用户签发的 virtual key」（service 层解析）。
// virtualKey 为空时不带 Authorization（本地无鉴权 litellm，便于 dev 联调）。
type Client interface {
	// ListModels 代理 litellm GET /v1/models，注入用户 virtualKey，返回上游原始响应（状态/头/体），脱敏在 handler 层做。
	ListModels(ctx context.Context, virtualKey string) (*ProxyResult, error)
	// ChatCompletions 代理 litellm POST /v1/chat/completions，注入用户 virtualKey，返回活体响应（不缓冲体），
	// 供 handler 流式逐 chunk 透传或非流式缓冲拷贝。body 为已注入 include_usage 的请求体。
	// 调用方负责关闭返回的 ChatResponse.Body。
	ChatCompletions(ctx context.Context, virtualKey string, body []byte) (*ChatResponse, error)
	// ImageGenerations 代理 litellm POST /v1/images/generations，注入用户 virtualKey。
	// OpenAI 图片接口始终为同步 JSON 响应（无 SSE），故复用 ProxyResult 缓冲返回，由 handler 透传。
	ImageGenerations(ctx context.Context, virtualKey string, body []byte) (*ProxyResult, error)
	// QianwenMultimodalGeneration 代理 litellm DashScope 透传端点
	// POST /qianwenai/api/v1/services/aigc/multimodal-generation/generation（如 qwen-image-2.0）。
	// 上游同步返回 JSON（image 在 output.choices[0].message.content[0].image），故同样缓冲返回。
	QianwenMultimodalGeneration(ctx context.Context, virtualKey string, body []byte) (*ProxyResult, error)
}

// qianwenMultimodalGenerationPath 是 litellm DashScope 透传端点的路径常量，与上游 1:1 对齐。
const qianwenMultimodalGenerationPath = "/qianwenai/api/v1/services/aigc/multimodal-generation/generation"

// ProxyResult 是 litellm 上游响应的原样载体（含非 2xx；OpenAI 错误体由上游/网关透传）。
type ProxyResult struct {
	Status int
	Header http.Header
	Body   []byte
}

// ChatResponse 是 litellm chat 响应的活体载体：Body 未读取，由 handler 决定流式泵或缓冲拷贝。
type ChatResponse struct {
	Status int
	Header http.Header
	Body   io.ReadCloser
}

// httpClient 是 Client 的真实 HTTP 实现：转发时注入按用户传入的 litellm virtual key（ADR-0014）。
type httpClient struct {
	baseURL string
	http    *http.Client
}

// NewHTTPClient 构造 litellm 代理客户端。virtual key 不再在构造期注入，改为每次调用按用户传入（ADR-0014）。
func NewHTTPClient(baseURL string, hc *http.Client) Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &httpClient{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

func (c *httpClient) ListModels(ctx context.Context, virtualKey string) (*ProxyResult, error) {
	return c.proxyGet(ctx, "/v1/models", virtualKey)
}

// ChatCompletions 转发 chat 请求，返回活体响应体（不读取、不关闭）。
// 关键：流式可达 30min，故此调用克隆出一个无客户端级 Timeout 的 client——
// 总时长/空闲由 handler 的 ctx deadline 与 PumpStream 治理，避免被 http.Client.Timeout（用于非流式）砍断。
func (c *httpClient) ChatCompletions(ctx context.Context, virtualKey string, body []byte) (*ChatResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("构造 litellm chat 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if virtualKey != "" {
		req.Header.Set("Authorization", "Bearer "+virtualKey)
	}

	hc := *c.http
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 litellm /v1/chat/completions 失败: %w", err)
	}
	return &ChatResponse{Status: resp.StatusCode, Header: resp.Header, Body: resp.Body}, nil
}

// ImageGenerations 转发图片生成请求并缓冲读完响应体。
// 与 chat 不同——图片接口同步返回 JSON（含 url 或 b64_json），无 SSE，无需 30min 大窗，沿用客户端默认 Timeout。
func (c *httpClient) ImageGenerations(ctx context.Context, virtualKey string, body []byte) (*ProxyResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/images/generations", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("构造 litellm images 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if virtualKey != "" {
		req.Header.Set("Authorization", "Bearer "+virtualKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 litellm /v1/images/generations 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 litellm images 响应失败: %w", err)
	}
	return &ProxyResult{Status: resp.StatusCode, Header: resp.Header, Body: respBody}, nil
}

// QianwenMultimodalGeneration 转发千问 DashScope 多模态生成请求并缓冲读完响应体。
// 与 ImageGenerations 同款语义——同步 JSON 返回（含 output.choices[0].message.content[0].image），无 SSE 大窗。
func (c *httpClient) QianwenMultimodalGeneration(ctx context.Context, virtualKey string, body []byte) (*ProxyResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+qianwenMultimodalGenerationPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("构造 litellm qianwen 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if virtualKey != "" {
		req.Header.Set("Authorization", "Bearer "+virtualKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 litellm %s 失败: %w", qianwenMultimodalGenerationPath, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 litellm qianwen 响应失败: %w", err)
	}
	return &ProxyResult{Status: resp.StatusCode, Header: resp.Header, Body: respBody}, nil
}

// proxyGet 执行一次 GET 转发，注入用户 virtual key，返回上游状态/头/体（非 2xx 也原样返回）。
func (c *httpClient) proxyGet(ctx context.Context, path, virtualKey string) (*ProxyResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 litellm 请求失败: %w", err)
	}
	if virtualKey != "" {
		req.Header.Set("Authorization", "Bearer "+virtualKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 litellm %s 失败: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 litellm 响应失败: %w", err)
	}
	return &ProxyResult{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}
