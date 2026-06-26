package clawhub

import (
	"context"
	"net/url"
	"strconv"
)

// ListParams 是 plugin 列表的查询参数（网关从对外请求透传到 ClawHub）。
// 空字段不下发，由 ClawHub 取默认。注意：兼容过滤（X-Platform/X-App-Version）走网关
// fetch-then-filter，不在此下发——ClawHub 返回全量、网关按 list 项元数据过滤（见 service.compat）。
type ListParams struct {
	Limit    int    // 单页条数；<=0 时不下发
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
//   - pluginCategory：ClawHub 承载浏览分类的原生字段，网关翻译为对外 category。
//   - HostTargets / MinAppVersion：网关 fetch-then-filter 所需的兼容元数据，
//     仅用于过滤、不外露（对外 PluginListItem 不含）。
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
	HostTargets      []string  `json:"hostTargets,omitempty"`
	MinAppVersion    string    `json:"minAppVersion,omitempty"`
}

// Compatibility 是制品兼容性元数据（plugin detail/version 携带，§3.7 桌面端装前自检）。
type Compatibility struct {
	PluginAPIRange           string   `json:"pluginApiRange,omitempty"`
	BuiltWithOpenClawVersion string   `json:"builtWithOpenClawVersion,omitempty"`
	PluginSDKVersion         string   `json:"pluginSdkVersion,omitempty"`
	MinGatewayVersion        string   `json:"minGatewayVersion,omitempty"`
	MinAppVersion            string   `json:"minAppVersion,omitempty"`
	HostTargets              []string `json:"hostTargets,omitempty"`
}

// VersionFile 是版本内文件清单项（完整性 / 指纹用）。
type VersionFile struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"contentType,omitempty"`
}

// PackageDetail 是 ClawHub GET /packages/{name} 的原始详情。
type PackageDetail struct {
	Package        PackageInfo            `json:"package"`
	LatestVersion  *PackageVersionSummary `json:"latestVersion"`
	Compatibility  *Compatibility         `json:"compatibility,omitempty"`
	PluginCategory *Category              `json:"pluginCategory"`
}

// PackageInfo 是 plugin 的元信息块。
type PackageInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Family      string `json:"family"`
	Channel     string `json:"channel"`
	IsOfficial  bool   `json:"isOfficial"`
}

// PackageVersionSummary 是 plugin 最新版本摘要（升级比较用）。
type PackageVersionSummary struct {
	Version   string `json:"version"`
	CreatedAt int64  `json:"createdAt"`
	Changelog string `json:"changelog"`
}

// PackageReleasePage 是 plugin 版本历史分页。
type PackageReleasePage struct {
	Items      []PackageReleaseHistory `json:"items"`
	NextCursor *string                 `json:"nextCursor"`
}

// PackageReleaseHistory 是 plugin 版本历史列表项（§3.2 PluginVersionHistory）。
type PackageReleaseHistory struct {
	Version   string   `json:"version"`
	CreatedAt int64    `json:"createdAt"`
	Changelog string   `json:"changelog"`
	DistTags  []string `json:"distTags,omitempty"`
}

// PackageReleaseDetail 是 ClawHub GET /packages/{name}/releases/{version} 的原始版本详情。
type PackageReleaseDetail struct {
	Package PackageReleasePkg `json:"package"`
	Version PackageRelease    `json:"version"`
}

// PackageReleasePkg 是版本详情内的精简 plugin 信息。
type PackageReleasePkg struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Family      string `json:"family"`
}

// PackageRelease 是 plugin 单版本的完整契约。
type PackageRelease struct {
	Version       string           `json:"version"`
	CreatedAt     int64            `json:"createdAt"`
	Changelog     string           `json:"changelog"`
	DistTags      []string         `json:"distTags,omitempty"`
	Files         []VersionFile    `json:"files,omitempty"`
	Compatibility *Compatibility   `json:"compatibility,omitempty"`
	Capabilities  map[string]any   `json:"capabilities,omitempty"`
	Artifact      *PackageArtifact `json:"artifact,omitempty"`
	SHA256Hash    string           `json:"sha256hash,omitempty"`
}

// PackageArtifact 是 plugin 制品归档信息。
type PackageArtifact struct {
	Kind   string `json:"kind"` // legacy-zip | npm-pack
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
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

	var page PackagePage
	if err := c.get(ctx, "/packages", q, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

func (c *httpClient) GetPackage(ctx context.Context, name string) (*PackageDetail, error) {
	var detail PackageDetail
	if err := c.get(ctx, "/packages/"+url.PathEscape(name), nil, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func (c *httpClient) GetPackageRelease(ctx context.Context, name, version string) (*PackageReleaseDetail, error) {
	path := "/packages/" + url.PathEscape(name) + "/releases/" + url.PathEscape(version)
	var detail PackageReleaseDetail
	if err := c.get(ctx, path, nil, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func (c *httpClient) ListPackageReleases(ctx context.Context, name string, page PageParams) (*PackageReleasePage, error) {
	q := url.Values{}
	if page.Limit > 0 {
		q.Set("limit", strconv.Itoa(page.Limit))
	}
	setIfNotEmpty(q, "cursor", page.Cursor)

	var out PackageReleasePage
	if err := c.get(ctx, "/packages/"+url.PathEscape(name)+"/versions", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *httpClient) PackageDownloadStreamURL(name, version string) string {
	u := c.baseURL + "/packages/" + url.PathEscape(name) + "/download"
	q := url.Values{}
	setIfNotEmpty(q, "version", version)
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	return u
}

func (c *httpClient) PackageArtifactStreamURL(name, version string) string {
	return c.baseURL + "/packages/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version) + "/artifact/download"
}
