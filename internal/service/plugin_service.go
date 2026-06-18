package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// Page 是游标分页的对外容器（对应 skill-plugin-lifecycle.md §2 Page<T>）。
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"nextCursor"`
}

// Category 是浏览分类的对外视图（§3.1b）。
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// PluginListItem 是 plugin 列表项的对外契约（§3.1）。
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

// PluginListParams 是 plugin 列表的对外查询参数（无搜索，sort+游标+filter）。
type PluginListParams struct {
	Limit    int
	Cursor   string
	Sort     string
	Family   string
	Channel  string
	Category string
}

// PluginService 把内网 ClawHub 的 packages 契约翻译为桌面端 plugin 契约（#19 曳光弹）。
type PluginService struct {
	hub clawhub.Client
}

// NewPluginService 构造服务。
func NewPluginService(hub clawhub.Client) *PluginService {
	return &PluginService{hub: hub}
}

// ListPlugins 转发到 ClawHub /packages 并翻译为 Page[PluginListItem]。
// ClawHub 的错误（*clawhub.Error / 传输失败）原样上抛，由 handler 按 ADR-0011 重映射。
func (s *PluginService) ListPlugins(ctx context.Context, params PluginListParams) (*Page[PluginListItem], error) {
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
		items = append(items, translatePackage(p))
	}
	return &Page[PluginListItem]{Items: items, NextCursor: page.NextCursor}, nil
}

// translatePackage 把 ClawHub PackageListItem 翻译为对外 PluginListItem。
// 关键翻译：ClawHub pluginCategory → 对外 category（§3.1b）；其余字段透传。
func translatePackage(p clawhub.PackageListItem) PluginListItem {
	var category *Category
	if p.PluginCategory != nil {
		category = &Category{ID: p.PluginCategory.ID, Label: p.PluginCategory.Label}
	}
	return PluginListItem{
		Name:             p.Name,
		DisplayName:      p.DisplayName,
		Summary:          p.Summary,
		Category:         category,
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
