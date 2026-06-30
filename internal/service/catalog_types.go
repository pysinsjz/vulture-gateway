package service

import (
	"sort"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// 本文件汇集 skill / plugin 两族共享的对外契约类型与翻译 helper。
// 对外类型与 ClawHub 内部类型刻意分离：翻译层（#20）负责把 ClawHub 契约整形为桌面端契约，
// 二者可独立演进（见 docs/flows/skill-plugin-lifecycle.md §2）。

// Page 是游标分页的对外容器（对应 §2 Page<T>）。
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"nextCursor"`
}

// Category 是浏览分类的对外视图（§3.1b）。
type Category struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// CategoryCount 是分类端点的对外项：分类 id/label + 该分类下可见制品数（§3.1b）。
type CategoryCount struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// CategoriesResponse 是分类端点（/skills/categories、/plugins/categories）的对外契约（§3.1b）。
type CategoriesResponse struct {
	Categories []CategoryCount `json:"categories"`
}

const (
	// uncategorizedID/uncategorizedLabel 是「未指定分类」可见制品的归并桶。
	// 契约约定未分类制品归「其他」（skill-plugin-lifecycle.md §3.1b）；派生口径下 category==nil
	// 即落此桶，且永远排在末位。
	uncategorizedID    = "other"
	uncategorizedLabel = "其他"

	// categoriesPageSize 是派生聚合翻页时下发的单页条数；
	// categoriesMaxPages 是翻页安全上限（防游标环 / 上游异常导致死循环）。
	categoriesPageSize = 100
	categoriesMaxPages = 1000
)

// buildCategoriesResponse 把 ClawHub 字典 + 制品 slug→count 计数表组装成对外响应。
//
// 规则（§3.1b 目标态，issue #44）：
//   1. 过滤 archived 项（ClawHub 公开 query 已源头过滤；此处是防御 + 单测可注入）。
//   2. 按字典 order 升序排（不信任上游一定排序；ClawHub 改了不破坏 gateway 契约）。
//   3. `other` 桶（uncategorizedID）强制末位（即便运营把 order 设到中间）。
//   4. 0 计数也输出（"招商中"信号，桌面端渲染占位）。
//   5. 制品 slug 命中字典 → 计入；不命中（字典里没有、archived 后字典消失、或 slug 为空）
//      → 累加到 `other` 桶兜底。
//
// counts 必含 uncategorizedID 桶（由调用方负责把未命中累加到该 key）。
func buildCategoriesResponse(dict []clawhub.CategoryDict, counts map[string]int) *CategoriesResponse {
	active := make([]clawhub.CategoryDict, 0, len(dict))
	for _, d := range dict {
		if d.Archived {
			continue
		}
		active = append(active, d)
	}

	sort.SliceStable(active, func(i, j int) bool { return active[i].Order < active[j].Order })

	out := make([]CategoryCount, 0, len(active)+1)
	var other *CategoryCount
	for _, d := range active {
		c := CategoryCount{ID: d.Slug, Label: d.Label, Count: counts[d.Slug]}
		if d.Slug == uncategorizedID {
			cc := c
			other = &cc
			continue
		}
		out = append(out, c)
	}
	if other == nil {
		other = &CategoryCount{ID: uncategorizedID, Label: uncategorizedLabel, Count: counts[uncategorizedID]}
	}
	out = append(out, *other)

	return &CategoriesResponse{Categories: out}
}

// resolveCategorySlug 把制品的 categorySlug 映射到字典里的 slug。空串 / 字典里没有的
// slug（如 archived 后从字典里消失的存量制品）→ `other`。
//
// active 由调用方按 buildCategoriesResponse 同款规则准备（archived 已过滤，未排序也行）。
func resolveCategorySlug(slug string, active map[string]struct{}) string {
	if slug == "" {
		return uncategorizedID
	}
	if _, ok := active[slug]; !ok {
		return uncategorizedID
	}
	return slug
}

// activeSlugSet 把字典转成 slug 集合（用于 resolveCategorySlug 的 O(1) 查表）。
// archived 项跳过——它们已不在字典语义内，相关存量制品应落 `other` 桶。
func activeSlugSet(dict []clawhub.CategoryDict) map[string]struct{} {
	set := make(map[string]struct{}, len(dict))
	for _, d := range dict {
		if d.Archived {
			continue
		}
		set[d.Slug] = struct{}{}
	}
	return set
}

// PageParams 是纯游标分页参数（版本历史等列表用）。
type PageParams struct {
	Limit  int
	Cursor string
}

// VersionFile 是版本内文件清单项（完整性 / 指纹用，§2）。
type VersionFile struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"contentType,omitempty"`
}

// Compatibility 是制品兼容性元数据（plugin detail/version 携带，§2 / §3.7）。
type Compatibility struct {
	PluginAPIRange           string   `json:"pluginApiRange,omitempty"`
	BuiltWithOpenClawVersion string   `json:"builtWithOpenClawVersion,omitempty"`
	PluginSDKVersion         string   `json:"pluginSdkVersion,omitempty"`
	MinGatewayVersion        string   `json:"minGatewayVersion,omitempty"`
	MinAppVersion            string   `json:"minAppVersion,omitempty"`
	HostTargets              []string `json:"hostTargets,omitempty"`
}

// translateCategory 把 ClawHub Category 翻译为对外 Category（nil 透传）。
func translateCategory(c *clawhub.Category) *Category {
	if c == nil {
		return nil
	}
	return &Category{ID: c.ID, Label: c.Label}
}

// translateCompat 把 ClawHub Compatibility 翻译为对外 Compatibility（nil 透传）。
func translateCompat(c *clawhub.Compatibility) *Compatibility {
	if c == nil {
		return nil
	}
	return &Compatibility{
		PluginAPIRange:           c.PluginAPIRange,
		BuiltWithOpenClawVersion: c.BuiltWithOpenClawVersion,
		PluginSDKVersion:         c.PluginSDKVersion,
		MinGatewayVersion:        c.MinGatewayVersion,
		MinAppVersion:            c.MinAppVersion,
		HostTargets:              c.HostTargets,
	}
}

// translateFiles 把 ClawHub VersionFile 列表翻译为对外形态。
func translateFiles(in []clawhub.VersionFile) []VersionFile {
	if in == nil {
		return nil
	}
	out := make([]VersionFile, 0, len(in))
	for _, f := range in {
		out = append(out, VersionFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256, ContentType: f.ContentType})
	}
	return out
}
