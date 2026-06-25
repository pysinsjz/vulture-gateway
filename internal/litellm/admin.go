package litellm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AdminClient 抽象 litellm 管理面契约（ADR-0014）：持 Master Key 签发/删除用户 virtual key，永不转发推理。
// 与 Proxy Client（Client）角色分离：Master Key 仅经此客户端使用，绝不进推理热路径。
type AdminClient interface {
	// GenerateKey 调 litellm POST /key/generate 签出一把 virtual key。
	GenerateKey(ctx context.Context, params GenerateKeyParams) (*GeneratedKey, error)
	// DeleteKey 调 litellm POST /key/delete 删除一把 key（按完整 key 字符串）。用于并发首签的孤儿回删与删用户接缝。
	DeleteKey(ctx context.Context, litellmKey string) error
}

// GenerateKeyParams 是签发参数（ADR-0014）：models 空＝全部（不下发该字段）；duration/rpm 不设；max_budget 为保险丝。
type GenerateKeyParams struct {
	KeyAlias  string   // key_alias=user-{uuid}
	UserID    string   // user_id={uuid}，litellm end-user 归因
	Models    []string // 空＝全部模型（访问控制是网关/套餐职责）
	MaxBudget float64  // 纵深防御保险丝（数值故意大到永不触发，B 当前挂空）
}

// GeneratedKey 是签发结果。Key 为完整 sk-...（落库+转发注入），TokenID 供改/删引用。
type GeneratedKey struct {
	Key     string
	TokenID string
}

type adminHTTPClient struct {
	baseURL   string
	masterKey string
	http      *http.Client
}

// NewAdminClient 构造 litellm 管理客户端。baseURL 必须与 masterKey 同实例，否则签发全 401（ADR-0014）。
func NewAdminClient(baseURL, masterKey string, hc *http.Client) AdminClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &adminHTTPClient{baseURL: strings.TrimRight(baseURL, "/"), masterKey: masterKey, http: hc}
}

func (c *adminHTTPClient) GenerateKey(ctx context.Context, params GenerateKeyParams) (*GeneratedKey, error) {
	payload := map[string]interface{}{
		"key_alias":  params.KeyAlias,
		"user_id":    params.UserID,
		"max_budget": params.MaxBudget,
	}
	// models 空＝全部：省略该字段让 litellm 用默认（全模型可达），非下发空数组（部分版本视空数组为无权）。
	if len(params.Models) > 0 {
		payload["models"] = params.Models
	}

	resBody, status, err := c.post(ctx, "/key/generate", payload)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("litellm /key/generate 返回 %d: %s", status, string(resBody))
	}

	var parsed struct {
		Key     string `json:"key"`
		TokenID string `json:"token_id"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(resBody, &parsed); err != nil {
		return nil, fmt.Errorf("解析 litellm /key/generate 响应失败: %w", err)
	}
	if parsed.Key == "" {
		return nil, fmt.Errorf("litellm /key/generate 未返回 key: %s", string(resBody))
	}
	tokenID := parsed.TokenID
	if tokenID == "" {
		tokenID = parsed.Token // 兼容仅返回 token 字段的版本
	}
	return &GeneratedKey{Key: parsed.Key, TokenID: tokenID}, nil
}

func (c *adminHTTPClient) DeleteKey(ctx context.Context, litellmKey string) error {
	resBody, status, err := c.post(ctx, "/key/delete", map[string]interface{}{"keys": []string{litellmKey}})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("litellm /key/delete 返回 %d: %s", status, string(resBody))
	}
	return nil
}

// post 发一次带 Master Key 鉴权的 JSON POST，返回响应体与状态码。
func (c *adminHTTPClient) post(ctx context.Context, path string, payload interface{}) ([]byte, int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("序列化 litellm 管理请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, fmt.Errorf("构造 litellm 管理请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.masterKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.masterKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("调用 litellm %s 失败: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("读取 litellm %s 响应失败: %w", path, err)
	}
	return body, resp.StatusCode, nil
}
