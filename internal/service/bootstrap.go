package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// feature_flags 注册表已登记键（bootstrap.md §2b）。桌面端只消费已登记键，未知 key 忽略（向前兼容）。
const (
	FlagMcpEnabled  = "mcp_enabled"   // bool，默认 false：E 域 MCP 入口扩展位
	FlagMaxUploadMB = "max_upload_mb" // number，默认 25：与 /v1/* 413 上限一致
)

// Notice 是一条运营公告（窗口过滤后下发）。
type Notice struct {
	ID       string `json:"id"`
	Level    string `json:"level"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	StartsAt int64  `json:"starts_at,omitempty"`
	EndsAt   int64  `json:"ends_at,omitempty"`
	URL      string `json:"url,omitempty"`
}

// BootstrapResponse 是启动引导聚合响应（bootstrap.md §2）。
// server_time 不参与 ETag（否则每秒变化使 304 失效）。app_update 本切片恒为 null（#29 接入）。
type BootstrapResponse struct {
	ServerTime     int64          `json:"server_time"`
	GatewayVersion string         `json:"gateway_version"`
	MinAppVersion  string         `json:"min_app_version,omitempty"`
	AppUpdate      *AppUpdate     `json:"app_update"`
	FeatureFlags   map[string]any `json:"feature_flags"`
	Notices        []Notice       `json:"notices"`
}

// BootstrapService 构建启动引导聚合响应并计算分桶 ETag（#28）。
type BootstrapService struct {
	gatewayVersion string
	minAppVersion  string
	mcpEnabled     bool
	maxUploadMB    int64
	notices        []Notice
}

// NewBootstrapService 构造服务。maxUploadMB 由调用方从 LLM 请求体上限派生（与 413 一致）。
func NewBootstrapService(gatewayVersion, minAppVersion string, mcpEnabled bool, maxUploadMB int64, notices []Notice) *BootstrapService {
	return &BootstrapService{
		gatewayVersion: gatewayVersion,
		minAppVersion:  minAppVersion,
		mcpEnabled:     mcpEnabled,
		maxUploadMB:    maxUploadMB,
		notices:        notices,
	}
}

// Build 按 (channel, appVersion, platform) 构建响应并计算 ETag。
// ETag 覆盖除 server_time 外的全部可缓存内容 + 三元组分桶维度；server_time 单独按 now 注入。
func (s *BootstrapService) Build(channel, appVersion, platform string, now time.Time) (BootstrapResponse, string) {
	flags := map[string]any{
		FlagMcpEnabled:  s.mcpEnabled,
		FlagMaxUploadMB: s.maxUploadMB,
	}
	notices := s.visibleNotices(now)

	resp := BootstrapResponse{
		ServerTime:     now.Unix(),
		GatewayVersion: s.gatewayVersion,
		MinAppVersion:  s.minAppVersion,
		AppUpdate:      nil, // 本切片恒 null；#29 接入 distribution 判定
		FeatureFlags:   flags,
		Notices:        notices,
	}
	etag := computeBootstrapETag(channel, appVersion, platform, s.gatewayVersion, s.minAppVersion, flags, notices)
	return resp, etag
}

// visibleNotices 按服务端时间过滤窗口：starts_at 未到或 ends_at 已过的公告不下发。
// 始终返回非 nil 切片（空公告序列化为 []）。
func (s *BootstrapService) visibleNotices(now time.Time) []Notice {
	ts := now.Unix()
	out := make([]Notice, 0, len(s.notices))
	for _, n := range s.notices {
		if n.StartsAt > 0 && ts < n.StartsAt {
			continue
		}
		if n.EndsAt > 0 && ts >= n.EndsAt {
			continue
		}
		out = append(out, n)
	}
	return out
}

// computeBootstrapETag 对分桶维度 + 可缓存内容做规范序列化后取 sha256，返回带引号的强 ETag。
// 不含 server_time：同桶同内容下 ETag 稳定，支撑 If-None-Match → 304。
func computeBootstrapETag(channel, appVersion, platform, gatewayVersion, minAppVersion string, flags map[string]any, notices []Notice) string {
	payload := struct {
		Channel        string         `json:"c"`
		AppVersion     string         `json:"a"`
		Platform       string         `json:"p"`
		GatewayVersion string         `json:"g"`
		MinAppVersion  string         `json:"m"`
		Flags          map[string]any `json:"f"`
		Notices        []Notice       `json:"n"`
	}{channel, appVersion, platform, gatewayVersion, minAppVersion, flags, notices}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
