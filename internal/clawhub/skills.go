package clawhub

import (
	"context"
	"net/url"
	"strconv"
)

// SkillListParams 是 skill 列表的查询参数。skill 无 family/channel，仅 sort + category filter；
// 兼容过滤（X-Platform）走网关 fetch-then-filter（按 metadata.systems/os），不在此下发。
type SkillListParams struct {
	Limit    int
	Cursor   string
	Sort     string // updated|downloads|stars|installsCurrent|trending
	Category string // 浏览分类 id（§3.1b）
}

// SkillPage 是 ClawHub /skills 的原始分页响应。
type SkillPage struct {
	Items      []SkillListItem `json:"items"`
	NextCursor *string         `json:"nextCursor"`
}

// SkillMetadata 是 skill 平台元数据（网关按 systems/os 做 X-Platform 过滤）。
type SkillMetadata struct {
	OS      []string `json:"os,omitempty"`
	Systems []string `json:"systems,omitempty"`
}

// SkillVersionSummary 是 skill 最新版本摘要。
type SkillVersionSummary struct {
	Version   string `json:"version"`
	CreatedAt int64  `json:"createdAt"`
	Changelog string `json:"changelog"`
	License   string `json:"license,omitempty"`
}

// SkillListItem 是 ClawHub 内部 skill 列表项。category 为 fork 原生字段（§5），网关透传。
// SkillCategorySlug 为 issue #44 引入的运营分类清单归属 slug；ClawHub#3 上线前响应里
// 缺失为空字符串，service 聚合时落 `other` 桶。
type SkillListItem struct {
	Slug             string               `json:"slug"`
	DisplayName      string               `json:"displayName"`
	Summary          string               `json:"summary,omitempty"`
	Category         *Category            `json:"category"`
	SkillCategorySlug string              `json:"skillCategorySlug,omitempty"`
	Tags             map[string]string    `json:"tags"`
	CreatedAt        int64                `json:"createdAt"`
	UpdatedAt        int64                `json:"updatedAt"`
	LatestVersion    *SkillVersionSummary `json:"latestVersion"`
	Metadata         *SkillMetadata       `json:"metadata"`
}

// SkillInfo 是 skill 详情的元信息块。
type SkillInfo struct {
	Slug              string            `json:"slug"`
	DisplayName       string            `json:"displayName"`
	Summary           string            `json:"summary,omitempty"`
	Category          *Category         `json:"category"`
	SkillCategorySlug string            `json:"skillCategorySlug,omitempty"`
	Tags              map[string]string `json:"tags"`
	CreatedAt         int64             `json:"createdAt"`
	UpdatedAt         int64             `json:"updatedAt"`
}

// SkillDetail 是 ClawHub GET /skills/{slug} 的原始详情。
type SkillDetail struct {
	Skill         SkillInfo            `json:"skill"`
	LatestVersion *SkillVersionSummary `json:"latestVersion"`
	Metadata      *SkillMetadata       `json:"metadata"`
}

// SkillVersionPage 是 skill 版本历史分页。
type SkillVersionPage struct {
	Items      []SkillVersionHistory `json:"items"`
	NextCursor *string               `json:"nextCursor"`
}

// SkillVersionHistory 是版本历史列表项。
type SkillVersionHistory struct {
	Version         string `json:"version"`
	CreatedAt       int64  `json:"createdAt"`
	Changelog       string `json:"changelog"`
	ChangelogSource string `json:"changelogSource,omitempty"`
}

// SkillVersionSkill 是版本详情内的精简 skill 信息。
type SkillVersionSkill struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"displayName"`
}

// SkillArtifact 是 skill 制品归档信息（下载完整性校验用）。
type SkillArtifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SkillVersion 是 skill 单版本的完整契约（含 artifact.sha256）。
type SkillVersion struct {
	Version         string        `json:"version"`
	CreatedAt       int64         `json:"createdAt"`
	Changelog       string        `json:"changelog"`
	ChangelogSource string        `json:"changelogSource,omitempty"`
	Files           []VersionFile `json:"files"`
	Artifact        SkillArtifact `json:"artifact"`
}

// SkillVersionDetail 是 ClawHub GET /skills/{slug}/versions/{version} 的原始版本详情。
type SkillVersionDetail struct {
	Skill   SkillVersionSkill `json:"skill"`
	Version SkillVersion      `json:"version"`
}

// ResolveVersion 是指纹解析结果中的版本引用。
type ResolveVersion struct {
	Version string `json:"version"`
}

// ResolveResult 是 ClawHub GET /skills/{slug}/resolve?hash= 的原始结果。
// Match==nil 表示本地指纹不匹配任何已发布版本（客户端据此辨因，§3.4）。
type ResolveResult struct {
	Slug          string          `json:"slug"`
	Match         *ResolveVersion `json:"match"`
	LatestVersion *ResolveVersion `json:"latestVersion"`
}

func (c *httpClient) ListSkills(ctx context.Context, params SkillListParams) (*SkillPage, error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	setIfNotEmpty(q, "cursor", params.Cursor)
	setIfNotEmpty(q, "sort", params.Sort)
	setIfNotEmpty(q, "category", params.Category)

	var page SkillPage
	if err := c.get(ctx, "/skills", q, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

func (c *httpClient) GetSkill(ctx context.Context, slug string) (*SkillDetail, error) {
	var detail SkillDetail
	if err := c.get(ctx, "/skills/"+url.PathEscape(slug), nil, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func (c *httpClient) ListSkillVersions(ctx context.Context, slug string, page PageParams) (*SkillVersionPage, error) {
	q := url.Values{}
	if page.Limit > 0 {
		q.Set("limit", strconv.Itoa(page.Limit))
	}
	setIfNotEmpty(q, "cursor", page.Cursor)

	var out SkillVersionPage
	if err := c.get(ctx, "/skills/"+url.PathEscape(slug)+"/versions", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *httpClient) GetSkillVersion(ctx context.Context, slug, version string) (*SkillVersionDetail, error) {
	path := "/skills/" + url.PathEscape(slug) + "/versions/" + url.PathEscape(version)
	var detail SkillVersionDetail
	if err := c.get(ctx, path, nil, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func (c *httpClient) ResolveSkill(ctx context.Context, slug, hash string) (*ResolveResult, error) {
	q := url.Values{}
	q.Set("hash", hash)

	var out ResolveResult
	if err := c.get(ctx, "/skills/"+url.PathEscape(slug)+"/resolve", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *httpClient) SkillDownloadStreamURL(slug, version string) string {
	q := url.Values{}
	q.Set("slug", slug)
	setIfNotEmpty(q, "version", version)
	return c.baseURL + "/download?" + q.Encode()
}

func (c *httpClient) ListSkillCategoriesDictionary(ctx context.Context) ([]CategoryDict, error) {
	var resp struct {
		Categories []CategoryDict `json:"categories"`
	}
	if err := c.get(ctx, "/skills/categories", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Categories, nil
}
