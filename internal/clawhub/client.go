// Package clawhub 是网关到内网 ClawHub（fork 裁剪版注册中心）的转发客户端。
//
// ClawHub 自身无鉴权、纯内网（见 docs/flows/clawhub-integration.md）：鉴权全部由网关的
// JWTAuth 承担，本客户端只做内网 HTTP 调用 + 取回 ClawHub 内部 skills/skillVersions、
// packages/packageReleases 等契约的原始形态。对外整形为桌面端契约（§3.1–3.4）由 service 层完成。
//
// 接口按 family 拆分（PackagesClient / SkillsClient），便于 service 层各取所需、用最小 fake 单测；
// 真实实现 httpClient 注入 *http.Client，端到端契约测试用 httptest 桩 ClawHub 驱动。
package clawhub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// PackagesClient 抽象内网 ClawHub 的 plugin（packages/packageReleases）只读契约。
type PackagesClient interface {
	// ListPackages 调用 ClawHub GET /packages，返回原始 plugin 列表（含网关侧过滤所需元数据）。
	ListPackages(ctx context.Context, params ListParams) (*PackagePage, error)
	// GetPackage 调用 ClawHub GET /packages/{name}，返回 plugin 详情（含 latestVersion + compatibility）。
	GetPackage(ctx context.Context, name string) (*PackageDetail, error)
	// GetPackageRelease 调用 ClawHub GET /packages/{name}/releases/{version}，返回指定版本详情。
	GetPackageRelease(ctx context.Context, name, version string) (*PackageReleaseDetail, error)
}

// SkillsClient 抽象内网 ClawHub 的 skill（skills/skillVersions）只读契约。
type SkillsClient interface {
	// ListSkills 调用 ClawHub GET /skills，返回原始 skill 列表。
	ListSkills(ctx context.Context, params SkillListParams) (*SkillPage, error)
	// GetSkill 调用 ClawHub GET /skills/{slug}，返回 skill 详情。
	GetSkill(ctx context.Context, slug string) (*SkillDetail, error)
	// ListSkillVersions 调用 ClawHub GET /skills/{slug}/versions，返回版本历史分页。
	ListSkillVersions(ctx context.Context, slug string, page PageParams) (*SkillVersionPage, error)
	// GetSkillVersion 调用 ClawHub GET /skills/{slug}/versions/{version}，返回指定版本详情（含 artifact.sha256）。
	GetSkillVersion(ctx context.Context, slug, version string) (*SkillVersionDetail, error)
	// ResolveSkill 调用 ClawHub GET /skills/{slug}/resolve?hash=，把本地指纹映射到已发布版本。
	ResolveSkill(ctx context.Context, slug, hash string) (*ResolveResult, error)
}

// Client 是两族契约的并集，由真实 httpClient 实现，供 wire 装配后分发给各 service。
type Client interface {
	PackagesClient
	SkillsClient
}

// PageParams 是纯游标分页参数（版本历史等无 filter 的列表用）。
type PageParams struct {
	Limit  int    // 单页条数；<=0 时不下发
	Cursor string // 游标分页 token
}

// Category 是浏览分类（id + label）。ClawHub 与对外契约同形。
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Error 表示 ClawHub 返回的非 2xx 响应。Status 用于网关侧错误重映射（ADR-0011）。
// 410（软删除）/ 423 / 409（pending）等业务状态码经此原样上抛，由 handler 透传。
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

// get 是统一的「GET → 校验状态码 → 解码 JSON」transport。非 2xx 解析为 *Error。
func (c *httpClient) get(ctx context.Context, path string, q url.Values, out any) error {
	endpoint := c.baseURL + path
	if enc := q.Encode(); enc != "" {
		endpoint += "?" + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("构造 ClawHub 请求失败: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("调用 ClawHub %s 失败: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取 ClawHub 响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseError(resp.StatusCode, body)
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("解析 ClawHub %s 响应失败: %w", path, err)
	}
	return nil
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
