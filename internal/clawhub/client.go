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
	"bytes"
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
	// ListPackageReleases 调用 ClawHub GET /packages/{name}/versions，返回 plugin 版本历史分页。
	ListPackageReleases(ctx context.Context, name string, page PageParams) (*PackageReleasePage, error)
	// PackageDownloadStreamURL 构造 plugin（legacy-zip）流式下载端点的绝对 URL：
	// GET {base}/packages/{name}/download?version=。网关反代此端点把字节透传回桌面端（interim
	// 路线 A）；安全门由 ClawHub 在该端点内强制（getReleaseSecurityBlock，返 403/410/451 等）。
	PackageDownloadStreamURL(name, version string) string
	// PackageArtifactStreamURL 构造 plugin（npm-pack .tgz）流式下载端点的绝对 URL：
	// GET {base}/packages/{name}/versions/{version}/artifact/download。
	PackageArtifactStreamURL(name, version string) string
	// PackageSecurity 调用 ClawHub GET /packages/{name}/releases/{version}/security，
	// 返回 PluginTrust（blockedFromDownload 为权威阻断信号，#22）。
	PackageSecurity(ctx context.Context, name, version string) (*PluginTrust, error)
	// ListPluginCategoriesDictionary 调用 ClawHub GET /plugins/categories，返回 plugin 族
	// 运营分类清单（已源头按 order 升序、archived 过滤）。网关侧聚合 categories 端点使用。
	ListPluginCategoriesDictionary(ctx context.Context) ([]CategoryDict, error)
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
	// SkillDownloadStreamURL 构造 skill 流式下载端点的绝对 URL：GET {base}/download?slug=&version=。
	// 网关反代此端点把字节透传回桌面端（interim 路线 A）；version 为空取 latest；安全门由 ClawHub
	// 在该端点内强制（getPublicSkillFileAccessBlock / decision=fail，返 403/410/451 等）。
	SkillDownloadStreamURL(slug, version string) string
	// SecurityVerdicts 调用 ClawHub POST /skills/-/security-verdicts，批量（1–100）返回安全裁决（#22）。
	SecurityVerdicts(ctx context.Context, items []VerdictRequestItem) (*SecurityVerdictResult, error)
	// ListSkillCategoriesDictionary 调用 ClawHub GET /skills/categories，返回 skill 族
	// 运营分类清单（已源头按 order 升序、archived 过滤）。网关侧聚合 categories 端点使用。
	ListSkillCategoriesDictionary(ctx context.Context) ([]CategoryDict, error)
}

// TelemetryClient 抽象内网 ClawHub 的安装遥测上报契约（§3.8）。
type TelemetryClient interface {
	// ReportInstall 调用 ClawHub POST /telemetry/install，按 root 状态快照对账（幂等，#22）。
	ReportInstall(ctx context.Context, report TelemetryReport) error
}

// Client 是各族契约的并集，由真实 httpClient 实现，供 wire 装配后分发给各 service。
type Client interface {
	PackagesClient
	SkillsClient
	TelemetryClient
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

// CategoryDict 是运营维护的分类清单项（plugin / skill 共用）。
//
// 来源：ClawHub GET /{plugins,skills}/categories 公开 query，响应已在源头按 order
// 升序、archived 过滤；故 Archived 在生产链路上恒为 false。保留该字段是为了：
//   - 让 service 层的"过滤 archived"防御逻辑可被 fake 单测覆盖；
//   - 与 PRD/issue body 的 service-layer 语义对齐（ADR 一致性）；
//   - 未来若 ClawHub 暴露 management query 给网关，无需改类型。
type CategoryDict struct {
	Slug     string `json:"slug"`
	Label    string `json:"label"`
	Order    int    `json:"order"`
	Archived bool   `json:"archived,omitempty"`
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
	return c.doRequest(req, path, out)
}

// post 是统一的「POST JSON → 校验状态码 →（可选）解码 JSON」transport。out 为 nil 时不解码响应体。
func (c *httpClient) post(ctx context.Context, path string, reqBody, out any) error {
	var rdr io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("序列化 ClawHub 请求体失败: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, rdr)
	if err != nil {
		return fmt.Errorf("构造 ClawHub 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doRequest(req, path, out)
}

// doRequest 执行请求并统一处理响应：非 2xx → *Error；out 非 nil 时解码 JSON。
func (c *httpClient) doRequest(req *http.Request, path string, out any) error {
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

	if out == nil {
		return nil
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
