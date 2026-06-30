package litellm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"
)

// AdminClient 抽象 litellm 管理面契约（ADR-0014/0016）：持 Master Key 签发/删除用户 virtual key + 列 team，永不转发推理。
// 与 Proxy Client（Client）角色分离：Master Key 仅经此客户端使用，绝不进推理热路径。
type AdminClient interface {
	// GenerateKey 调 litellm POST /key/generate 签出一把 virtual key。
	GenerateKey(ctx context.Context, params GenerateKeyParams) (*GeneratedKey, error)
	// DeleteKey 调 litellm POST /key/delete 删除一把 key（按完整 key 字符串）。用于并发首签的孤儿回删与删用户接缝。
	DeleteKey(ctx context.Context, litellmKey string) error
	// ListTeams 调 litellm GET /team/list 拉当前所有 team（ADR-0016）。
	// 签发前用于把 default_team_alias 解析为 team_id；不缓存（team 重建立刻恢复）。
	// litellm /team/list 默认不分页，team 数预期 <10；超出后再加分页。
	ListTeams(ctx context.Context) ([]Team, error)
}

// Team 是 litellm /team/list 的精简响应（ADR-0016）：只保留签发解析需要的两字段。
// litellm 响应还含 spend/budget/models 等，本结构有意不暴露——业务只用 alias 寻址。
type Team struct {
	ID    string `json:"team_id"`
	Alias string `json:"team_alias"`
}

// GenerateKeyParams 是签发参数（ADR-0014/0016）：team_id 控制模型权限；models 字段彻底不下发；max_budget 为保险丝。
type GenerateKeyParams struct {
	KeyAlias  string  // key_alias=user-{uuid}
	UserID    string  // user_id={uuid}，litellm end-user 归因
	TeamID    string  // team_id={uuid}，签发归属 team；team 的 models 列表决定 key 可达模型（ADR-0016）
	MaxBudget float64 // 纵深防御保险丝（数值故意大到永不触发，B 当前挂空）
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
	// ADR-0016：team_id 非空时下发；省略 models 字段（team 的 models 列表是模型权限单一真相源）。
	// 实测 workaround litellm bug #3275：省略 models 让 /v1/models 自动展开 team 真实模型清单。
	if params.TeamID != "" {
		payload["team_id"] = params.TeamID
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

func (c *adminHTTPClient) ListTeams(ctx context.Context) ([]Team, error) {
	resBody, status, err := c.get(ctx, "/team/list")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("litellm /team/list 返回 %d: %s", status, string(resBody))
	}
	// litellm /team/list 大多直接返数组；个别版本可能包成 {"data":[...]} 字典壳。
	// 跳过前导空白再判首字符（防服务器返 "  [..." 这种合法但带缩进的 JSON）。
	trimmed := bytes.TrimLeftFunc(resBody, unicode.IsSpace)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var teams []Team
		if err := json.Unmarshal(resBody, &teams); err != nil {
			return nil, fmt.Errorf("解析 litellm /team/list 响应失败: %w", err)
		}
		return teams, nil
	}
	var wrapped struct {
		Data []Team `json:"data"`
	}
	if err := json.Unmarshal(resBody, &wrapped); err != nil {
		return nil, fmt.Errorf("解析 litellm /team/list 响应失败: %w", err)
	}
	return wrapped.Data, nil
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

// get 发一次带 Master Key 鉴权的 GET，返回响应体与状态码（ADR-0016，用于 /team/list 等只读端点）。
func (c *adminHTTPClient) get(ctx context.Context, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("构造 litellm 管理请求失败: %w", err)
	}
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
