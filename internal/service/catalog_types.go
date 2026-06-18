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
