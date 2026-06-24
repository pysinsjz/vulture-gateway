package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// PluginListItem 是 plugin 列表项的对外契约（§3.1）。不含 hostTargets/minAppVersion——
// 那些仅用于网关侧兼容过滤，翻译时剥离。
type PluginListItem struct {
	Name             string    `json:"name"`
	DisplayName      string    `json:"displayName"`
	Summary          string    `json:"summary,omitempty"`
	Category         *Category `json:"category"`
	Family           string    `json:"family"`
	Channel          string    `json:"channel"`
	IsOfficial       bool      `json:"isOfficial"`
	LatestVersion    string    `json:"latestVersion,omitempty"`
	CapabilityTags   []string  `json:"capabilityTags,omitempty"`
	ExecutesCode     *bool     `json:"executesCode,omitempty"`
	VerificationTier string    `json:"verificationTier,omitempty"`
	ScanStatus       string    `json:"scanStatus,omitempty"`
}

// PluginInfo 是 plugin 详情的元信息块（§3.2 PluginDetail.package）。
type PluginInfo struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	Family      string    `json:"family"`
	Channel     string    `json:"channel"`
	IsOfficial  bool      `json:"isOfficial"`
	Category    *Category `json:"category"`
}

// PluginVersionSummary 是 plugin 最新版本摘要（升级比较取 version）。
type PluginVersionSummary struct {
	Version   string `json:"version"`
	CreatedAt int64  `json:"createdAt"`
	Changelog string `json:"changelog"`
}

// PluginDetail 是 plugin 详情的对外契约（§3.2）。
type PluginDetail struct {
	Package       PluginInfo            `json:"package"`
	LatestVersion *PluginVersionSummary `json:"latestVersion"`
	Compatibility *Compatibility        `json:"compatibility,omitempty"`
}

// PluginVersionPkg 是 plugin 版本详情内的精简包信息（§3.2 PluginVersionDetail.package）。
type PluginVersionPkg struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Family      string `json:"family"`
}

// PluginArtifact 是 plugin 制品归档信息（§3.2）。
type PluginArtifact struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// PluginVersionBody 是 plugin 单版本契约的 version 块。
type PluginVersionBody struct {
	Version       string          `json:"version"`
	CreatedAt     int64           `json:"createdAt"`
	Changelog     string          `json:"changelog"`
	DistTags      []string        `json:"distTags,omitempty"`
	Files         []VersionFile   `json:"files,omitempty"`
	Compatibility *Compatibility  `json:"compatibility,omitempty"`
	Capabilities  map[string]any  `json:"capabilities,omitempty"`
	Artifact      *PluginArtifact `json:"artifact,omitempty"`
	SHA256Hash    string          `json:"sha256hash,omitempty"`
}

// PluginVersionDetail 是 plugin 指定版本的对外契约（§3.2）。
type PluginVersionDetail struct {
	Package PluginVersionPkg  `json:"package"`
	Version PluginVersionBody `json:"version"`
}

// PluginListParams 是 plugin 列表的对外查询参数（无搜索，sort+游标+filter）。
type PluginListParams struct {
	Limit    int
	Cursor   string
	Sort     string
	Family   string
	Channel  string
	Category string
}

// PluginService 把内网 ClawHub 的 packages/packageReleases 契约翻译为桌面端 plugin 契约（#19/#20）。
type PluginService struct {
	hub clawhub.PackagesClient
}

// NewPluginService 构造服务。
func NewPluginService(hub clawhub.PackagesClient) *PluginService {
	return &PluginService{hub: hub}
}

// ListPlugins 转发到 ClawHub /packages，按 X-Platform/X-App-Version 兼容过滤（fetch-then-filter），
// 再翻译为 Page[PluginListItem]。ClawHub 错误原样上抛，由 handler 按 ADR-0011 重映射。
func (s *PluginService) ListPlugins(ctx context.Context, params PluginListParams, cc CompatContext) (*Page[PluginListItem], error) {
	page, err := s.hub.ListPackages(ctx, clawhub.ListParams{
		Limit:    params.Limit,
		Cursor:   params.Cursor,
		Sort:     params.Sort,
		Family:   params.Family,
		Channel:  params.Channel,
		Category: params.Category,
	})
	if err != nil {
		return nil, err
	}

	items := make([]PluginListItem, 0, len(page.Items))
	for _, p := range page.Items {
		if !compatiblePackage(p, cc) {
			continue
		}
		items = append(items, translatePackage(p))
	}
	return &Page[PluginListItem]{Items: items, NextCursor: page.NextCursor}, nil
}

// GetPlugin 转发到 ClawHub /packages/{name} 并翻译为 PluginDetail。
func (s *PluginService) GetPlugin(ctx context.Context, name string) (*PluginDetail, error) {
	d, err := s.hub.GetPackage(ctx, name)
	if err != nil {
		return nil, err
	}

	detail := &PluginDetail{
		Package: PluginInfo{
			Name:        d.Package.Name,
			DisplayName: d.Package.DisplayName,
			Family:      d.Package.Family,
			Channel:     d.Package.Channel,
			IsOfficial:  d.Package.IsOfficial,
			Category:    translateCategory(d.PluginCategory),
		},
		Compatibility: translateCompat(d.Compatibility),
	}
	if d.LatestVersion != nil {
		detail.LatestVersion = &PluginVersionSummary{
			Version:   d.LatestVersion.Version,
			CreatedAt: d.LatestVersion.CreatedAt,
			Changelog: d.LatestVersion.Changelog,
		}
	}
	return detail, nil
}

// GetPluginVersion 转发到 ClawHub /packages/{name}/releases/{version} 并翻译为 PluginVersionDetail。
func (s *PluginService) GetPluginVersion(ctx context.Context, name, version string) (*PluginVersionDetail, error) {
	d, err := s.hub.GetPackageRelease(ctx, name, version)
	if err != nil {
		return nil, err
	}

	body := PluginVersionBody{
		Version:       d.Version.Version,
		CreatedAt:     d.Version.CreatedAt,
		Changelog:     d.Version.Changelog,
		DistTags:      d.Version.DistTags,
		Files:         translateFiles(d.Version.Files),
		Compatibility: translateCompat(d.Version.Compatibility),
		Capabilities:  d.Version.Capabilities,
		SHA256Hash:    d.Version.SHA256Hash,
	}
	if d.Version.Artifact != nil {
		body.Artifact = &PluginArtifact{
			Kind:   d.Version.Artifact.Kind,
			SHA256: d.Version.Artifact.SHA256,
			Size:   d.Version.Artifact.Size,
		}
	}
	return &PluginVersionDetail{
		Package: PluginVersionPkg{Name: d.Package.Name, DisplayName: d.Package.DisplayName, Family: d.Package.Family},
		Version: body,
	}, nil
}

// DownloadStreamURL 返回 plugin（legacy-zip）流式下载端点的绝对 URL，供网关反代字节透传回桌面端
// （interim 路线 A）。安全门由 ClawHub 在该端点内强制（getReleaseSecurityBlock → 403/410/451），
// 反代时原样透传状态码（#21）。
func (s *PluginService) DownloadStreamURL(name, version string) string {
	return s.hub.PackageDownloadStreamURL(name, version)
}

// ArtifactStreamURL 返回 plugin（npm-pack .tgz）流式下载端点的绝对 URL。
func (s *PluginService) ArtifactStreamURL(name, version string) string {
	return s.hub.PackageArtifactStreamURL(name, version)
}

// translatePackage 把 ClawHub PackageListItem 翻译为对外 PluginListItem。
// 关键翻译：pluginCategory → category（§3.1b）；剥离 hostTargets/minAppVersion；其余字段透传。
func translatePackage(p clawhub.PackageListItem) PluginListItem {
	return PluginListItem{
		Name:             p.Name,
		DisplayName:      p.DisplayName,
		Summary:          p.Summary,
		Category:         translateCategory(p.PluginCategory),
		Family:           p.Family,
		Channel:          p.Channel,
		IsOfficial:       p.IsOfficial,
		LatestVersion:    p.LatestVersion,
		CapabilityTags:   p.CapabilityTags,
		ExecutesCode:     p.ExecutesCode,
		VerificationTier: p.VerificationTier,
		ScanStatus:       p.ScanStatus,
	}
}
