package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// SkillMetadata 是 skill 平台元数据的对外视图（§3.1）。
type SkillMetadata struct {
	OS      []string `json:"os,omitempty"`
	Systems []string `json:"systems,omitempty"`
}

// SkillVersionSummary 是 skill 最新版本摘要（§3.1 latestVersion）。
type SkillVersionSummary struct {
	Version   string `json:"version"`
	CreatedAt int64  `json:"createdAt"`
	Changelog string `json:"changelog"`
	License   string `json:"license,omitempty"`
}

// SkillListItem 是 skill 列表项的对外契约（§3.1）。
type SkillListItem struct {
	Slug          string               `json:"slug"`
	DisplayName   string               `json:"displayName"`
	Summary       string               `json:"summary,omitempty"`
	Category      *Category            `json:"category"`
	Tags          map[string]string    `json:"tags"`
	CreatedAt     int64                `json:"createdAt"`
	UpdatedAt     int64                `json:"updatedAt"`
	LatestVersion *SkillVersionSummary `json:"latestVersion"`
	Metadata      *SkillMetadata       `json:"metadata"`
}

// SkillInfo 是 skill 详情的元信息块（§3.2 SkillDetail.skill）。
type SkillInfo struct {
	Slug        string            `json:"slug"`
	DisplayName string            `json:"displayName"`
	Summary     string            `json:"summary,omitempty"`
	Category    *Category         `json:"category"`
	Tags        map[string]string `json:"tags"`
	CreatedAt   int64             `json:"createdAt"`
	UpdatedAt   int64             `json:"updatedAt"`
}

// SkillDetail 是 skill 详情的对外契约（§3.2）。
type SkillDetail struct {
	Skill         SkillInfo            `json:"skill"`
	LatestVersion *SkillVersionSummary `json:"latestVersion"`
	Metadata      *SkillMetadata       `json:"metadata"`
}

// SkillVersionHistory 是 skill 版本历史列表项（§3.2）。
type SkillVersionHistory struct {
	Version         string `json:"version"`
	CreatedAt       int64  `json:"createdAt"`
	Changelog       string `json:"changelog"`
	ChangelogSource string `json:"changelogSource,omitempty"`
}

// SkillVersionSkill 是 skill 版本详情内的精简信息（§3.2）。
type SkillVersionSkill struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"displayName"`
}

// SkillArtifact 是 skill 制品归档信息（下载完整性校验用，§3.2）。
type SkillArtifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SkillVersionBody 是 skill 单版本契约的 version 块。
type SkillVersionBody struct {
	Version         string        `json:"version"`
	CreatedAt       int64         `json:"createdAt"`
	Changelog       string        `json:"changelog"`
	ChangelogSource string        `json:"changelogSource,omitempty"`
	Files           []VersionFile `json:"files"`
	Artifact        SkillArtifact `json:"artifact"`
}

// SkillVersionDetail 是 skill 指定版本的对外契约（含 artifact.sha256，§3.2）。
type SkillVersionDetail struct {
	Skill   SkillVersionSkill `json:"skill"`
	Version SkillVersionBody  `json:"version"`
}

// ResolveVersion 是指纹解析结果中的版本引用（§3.4）。
type ResolveVersion struct {
	Version string `json:"version"`
}

// ResolveResponse 是指纹更新检测的对外结果（§3.4）。
// Match==nil 表示本地指纹不匹配任何已发布版本，客户端据 origin.fingerprint 辨因。
type ResolveResponse struct {
	Slug          string          `json:"slug"`
	Match         *ResolveVersion `json:"match"`
	LatestVersion *ResolveVersion `json:"latestVersion"`
}

// SkillListParams 是 skill 列表的对外查询参数（无搜索，sort+游标+category filter）。
type SkillListParams struct {
	Limit    int
	Cursor   string
	Sort     string
	Category string
}

// SkillService 把内网 ClawHub 的 skills/skillVersions 契约翻译为桌面端 skill 契约（#20）。
type SkillService struct {
	hub clawhub.SkillsClient
}

// NewSkillService 构造服务。
func NewSkillService(hub clawhub.SkillsClient) *SkillService {
	return &SkillService{hub: hub}
}

// ListSkills 转发到 ClawHub /skills，按 X-Platform 兼容过滤（metadata.systems/os），再翻译。
func (s *SkillService) ListSkills(ctx context.Context, params SkillListParams, cc CompatContext) (*Page[SkillListItem], error) {
	page, err := s.hub.ListSkills(ctx, clawhub.SkillListParams{
		Limit:    params.Limit,
		Cursor:   params.Cursor,
		Sort:     params.Sort,
		Category: params.Category,
	})
	if err != nil {
		return nil, err
	}

	items := make([]SkillListItem, 0, len(page.Items))
	for _, sk := range page.Items {
		if !compatibleSkill(sk.Metadata, cc) {
			continue
		}
		items = append(items, translateSkillListItem(sk))
	}
	return &Page[SkillListItem]{Items: items, NextCursor: page.NextCursor}, nil
}

// GetSkill 转发到 ClawHub /skills/{slug} 并翻译为 SkillDetail。
func (s *SkillService) GetSkill(ctx context.Context, slug string) (*SkillDetail, error) {
	d, err := s.hub.GetSkill(ctx, slug)
	if err != nil {
		return nil, err
	}
	return &SkillDetail{
		Skill: SkillInfo{
			Slug:        d.Skill.Slug,
			DisplayName: d.Skill.DisplayName,
			Summary:     d.Skill.Summary,
			Category:    translateCategory(d.Skill.Category),
			Tags:        d.Skill.Tags,
			CreatedAt:   d.Skill.CreatedAt,
			UpdatedAt:   d.Skill.UpdatedAt,
		},
		LatestVersion: translateSkillVersionSummary(d.LatestVersion),
		Metadata:      translateSkillMetadata(d.Metadata),
	}, nil
}

// ListSkillVersions 转发到 ClawHub /skills/{slug}/versions 并翻译为版本历史分页。
func (s *SkillService) ListSkillVersions(ctx context.Context, slug string, page PageParams) (*Page[SkillVersionHistory], error) {
	out, err := s.hub.ListSkillVersions(ctx, slug, clawhub.PageParams{Limit: page.Limit, Cursor: page.Cursor})
	if err != nil {
		return nil, err
	}

	items := make([]SkillVersionHistory, 0, len(out.Items))
	for _, v := range out.Items {
		items = append(items, SkillVersionHistory{
			Version:         v.Version,
			CreatedAt:       v.CreatedAt,
			Changelog:       v.Changelog,
			ChangelogSource: v.ChangelogSource,
		})
	}
	return &Page[SkillVersionHistory]{Items: items, NextCursor: out.NextCursor}, nil
}

// GetSkillVersion 转发到 ClawHub /skills/{slug}/versions/{version} 并翻译为 SkillVersionDetail。
func (s *SkillService) GetSkillVersion(ctx context.Context, slug, version string) (*SkillVersionDetail, error) {
	d, err := s.hub.GetSkillVersion(ctx, slug, version)
	if err != nil {
		return nil, err
	}
	return &SkillVersionDetail{
		Skill: SkillVersionSkill{Slug: d.Skill.Slug, DisplayName: d.Skill.DisplayName},
		Version: SkillVersionBody{
			Version:         d.Version.Version,
			CreatedAt:       d.Version.CreatedAt,
			Changelog:       d.Version.Changelog,
			ChangelogSource: d.Version.ChangelogSource,
			Files:           translateFiles(d.Version.Files),
			Artifact:        SkillArtifact{SHA256: d.Version.Artifact.SHA256, Size: d.Version.Artifact.Size},
		},
	}, nil
}

// ResolveSkill 转发到 ClawHub /skills/{slug}/resolve?hash= 并翻译为 ResolveResponse。
func (s *SkillService) ResolveSkill(ctx context.Context, slug, hash string) (*ResolveResponse, error) {
	r, err := s.hub.ResolveSkill(ctx, slug, hash)
	if err != nil {
		return nil, err
	}
	return &ResolveResponse{
		Slug:          r.Slug,
		Match:         translateResolveVersion(r.Match),
		LatestVersion: translateResolveVersion(r.LatestVersion),
	}, nil
}

// DownloadStreamURL 返回 skill 流式下载端点的绝对 URL，供网关反代把字节透传回桌面端（interim
// 路线 A，见 handler.downloadProxy）。version 为空取 latest；安全门由 ClawHub 在该端点内强制
// （decision=fail / getPublicSkillFileAccessBlock → 403/410/451），反代时原样透传状态码（#21）。
func (s *SkillService) DownloadStreamURL(slug, version string) string {
	return s.hub.SkillDownloadStreamURL(slug, version)
}

func translateSkillListItem(sk clawhub.SkillListItem) SkillListItem {
	return SkillListItem{
		Slug:          sk.Slug,
		DisplayName:   sk.DisplayName,
		Summary:       sk.Summary,
		Category:      translateCategory(sk.Category),
		Tags:          sk.Tags,
		CreatedAt:     sk.CreatedAt,
		UpdatedAt:     sk.UpdatedAt,
		LatestVersion: translateSkillVersionSummary(sk.LatestVersion),
		Metadata:      translateSkillMetadata(sk.Metadata),
	}
}

func translateSkillVersionSummary(v *clawhub.SkillVersionSummary) *SkillVersionSummary {
	if v == nil {
		return nil
	}
	return &SkillVersionSummary{Version: v.Version, CreatedAt: v.CreatedAt, Changelog: v.Changelog, License: v.License}
}

func translateSkillMetadata(m *clawhub.SkillMetadata) *SkillMetadata {
	if m == nil {
		return nil
	}
	return &SkillMetadata{OS: m.OS, Systems: m.Systems}
}

func translateResolveVersion(v *clawhub.ResolveVersion) *ResolveVersion {
	if v == nil {
		return nil
	}
	return &ResolveVersion{Version: v.Version}
}
