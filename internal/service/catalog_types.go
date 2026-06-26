package service

import "github.com/pysinsjz/vulture-gateway/internal/clawhub"

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

// categoryAggregator 累计「分类 → 可见制品数」，保持分类的首次出现顺序，
// category==nil 的可见制品归入末位「其他」桶。
//
// 派生口径的已知偏差（§3.1b「网关派生」分支）：
//   - 顺序为首现序（列表默认排序决定），非运营定义序；
//   - 0 可见制品的分类不会出现（派生只见列表里实际出现过的分类）。
//
// 目标态由 ClawHub fork 原生分类端点取代（见 docs/flows/clawhub-gateway-contract.md）。
type categoryAggregator struct {
	order      []string          // 首现顺序的分类 id
	labels     map[string]string // id → label（同 id 以首现 label 为准）
	counts     map[string]int    // id → 可见制品数
	uncatCount int               // 未分类（category==nil）可见制品数
}

func newCategoryAggregator() *categoryAggregator {
	return &categoryAggregator{labels: map[string]string{}, counts: map[string]int{}}
}

// add 累计一个可见制品的分类。调用方负责仅传入「通过兼容过滤」的制品。
func (a *categoryAggregator) add(cat *Category) {
	if cat == nil {
		a.uncatCount++
		return
	}
	if _, seen := a.counts[cat.ID]; !seen {
		a.order = append(a.order, cat.ID)
		a.labels[cat.ID] = cat.Label
	}
	a.counts[cat.ID]++
}

// result 按首现序输出分类计数；末位追加「其他」桶（仅当存在未分类可见制品）。
func (a *categoryAggregator) result() CategoriesResponse {
	cats := make([]CategoryCount, 0, len(a.order)+1)
	for _, id := range a.order {
		cats = append(cats, CategoryCount{ID: id, Label: a.labels[id], Count: a.counts[id]})
	}
	if a.uncatCount > 0 {
		cats = append(cats, CategoryCount{ID: uncategorizedID, Label: uncategorizedLabel, Count: a.uncatCount})
	}
	return CategoriesResponse{Categories: cats}
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
