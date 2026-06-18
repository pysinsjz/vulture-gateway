// Package clawhub 是网关到内网 ClawHub（fork 裁剪版注册中心）的转发客户端。
//
// ClawHub 自身无鉴权、纯内网（见 docs/flows/clawhub-integration.md）：鉴权全部由网关的
// JWTAuth 承担，本客户端只做内网 HTTP 调用 + 取回 ClawHub 内部 /packages 等契约的原始形态。
// 对外整形为桌面端契约（§3.1 PluginListItem 等）由 service 层完成。
//
// Client 为接口，便于 service 层用 fake 做单测；真实实现 httpClient 注入 *http.Client，
// 端到端契约测试用 httptest 桩 ClawHub 驱动（见 client_test.go 与 router 层契约测试）。
package clawhub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client 抽象内网 ClawHub 的只读查询契约。随 #20 端点翻译铺满逐步扩展。
type Client interface {
	// ListPackages 调用 ClawHub 内部 GET /packages，返回原始 plugin 列表契约。
	ListPackages(ctx context.Context, params ListParams) (*PackagePage, error)
}

// ListParams 是 plugin 列表的查询参数（网关从对外请求透传到 ClawHub）。
// 空字段不下发，由 ClawHub 取默认。完整 filter 覆盖见 #20。
type ListParams struct {
	Limit    int    // 单页条数；<=0 时不下发（ClawHub 取默认）
	Cursor   string // 游标分页 token
	Sort     string // 排序键：updated|downloads|stars|installsCurrent|trending
	Family   string // code-plugin|bundle-plugin
	Channel  string // official|community|private
	Category string // 浏览分类 id（§3.1b）
}

// PackagePage 是 ClawHub /packages 的原始分页响应。
type PackagePage struct {
	Items      []PackageListItem `json:"items"`
	NextCursor *string           `json:"nextCursor"`
}

// PackageListItem 是 ClawHub 内部 plugin 列表项的原始形态。
// 注意 ClawHub 用 pluginCategory 承载浏览分类；网关在 service 层翻译为对外的 category。
type PackageListItem struct {
	Name             string    `json:"name"`
	DisplayName      string    `json:"displayName"`
	Summary          string    `json:"summary,omitempty"`
	PluginCategory   *Category `json:"pluginCategory"`
	Family           string    `json:"family"`
	Channel          string    `json:"channel"`
	IsOfficial       bool      `json:"isOfficial"`
	LatestVersion    string    `json:"latestVersion,omitempty"`
	CapabilityTags   []string  `json:"capabilityTags,omitempty"`
	ExecutesCode     *bool     `json:"executesCode,omitempty"`
	VerificationTier string    `json:"verificationTier,omitempty"`
	ScanStatus       string    `json:"scanStatus,omitempty"`
}

// Category 是浏览分类（id + label）。ClawHub 与对外契约同形。
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Error 表示 ClawHub 返回的非 2xx 响应。Status 用于网关侧错误重映射（ADR-0011）。
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("clawhub: status=%d code=%s message=%s", e.Status, e.Code, e.Message)
}

// httpClient 是 Client 的真实 HTTP 实现：内网直连 ClawHub，不带鉴权头。
type httpClient struct {
	baseURL string
	http    *http.Client
}

// NewHTTPClient 构造内网 ClawHub HTTP 客户端。baseURL 形如 http://clawhub.internal:3210。
// hc 为 nil 时退回 http.DefaultClient。
func NewHTTPClient(baseURL string, hc *http.Client) Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &httpClient{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

func (c *httpClient) ListPackages(ctx context.Context, params ListParams) (*PackagePage, error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	setIfNotEmpty(q, "cursor", params.Cursor)
	setIfNotEmpty(q, "sort", params.Sort)
	setIfNotEmpty(q, "family", params.Family)
	setIfNotEmpty(q, "channel", params.Channel)
	setIfNotEmpty(q, "category", params.Category)

	endpoint := c.baseURL + "/packages"
	if enc := q.Encode(); enc != "" {
		endpoint += "?" + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 ClawHub 请求失败: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 ClawHub /packages 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 ClawHub 响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp.StatusCode, body)
	}

	var page PackagePage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("解析 ClawHub /packages 响应失败: %w", err)
	}
	return &page, nil
}

// parseError 把 ClawHub 非 2xx 响应解析为 *Error。ClawHub 错误体尽量贴 {error,message}，
// 解析失败则以原始 body 作 message 兜底。
func parseError(status int, body []byte) *Error {
	var e struct {
		Code    string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err == nil && (e.Code != "" || e.Message != "") {
		return &Error{Status: status, Code: e.Code, Message: e.Message}
	}
	return &Error{Status: status, Message: strings.TrimSpace(string(body))}
}

func setIfNotEmpty(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}
