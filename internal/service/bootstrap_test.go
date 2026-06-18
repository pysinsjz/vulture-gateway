package service_test

import (
	"testing"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/service"
)

func newBootstrap(notices ...service.Notice) *service.BootstrapService {
	return service.NewBootstrapService("1.4.2", "1.2.0", false, 25, notices, nil)
}

// feature_flags：按注册表登记键与类型返回（mcp_enabled bool / max_upload_mb number）。
func TestBootstrap_FeatureFlagsRegistry(t *testing.T) {
	s := newBootstrap()
	resp, _ := s.Build("stable", "1.0.0", "darwin-arm64", time.Unix(1000, 0))

	if len(resp.FeatureFlags) != 2 {
		t.Fatalf("应只发已登记的 2 个 flag, 实际 %v", resp.FeatureFlags)
	}
	if v, ok := resp.FeatureFlags[service.FlagMcpEnabled].(bool); !ok || v != false {
		t.Errorf("mcp_enabled 应为 bool false, 实际 %v", resp.FeatureFlags[service.FlagMcpEnabled])
	}
	if v, ok := resp.FeatureFlags[service.FlagMaxUploadMB].(int64); !ok || v != 25 {
		t.Errorf("max_upload_mb 应为 number 25, 实际 %v", resp.FeatureFlags[service.FlagMaxUploadMB])
	}
	if resp.AppUpdate != nil {
		t.Error("本切片 app_update 应为 null")
	}
	if resp.ServerTime != 1000 {
		t.Errorf("server_time 应为 now, 实际 %d", resp.ServerTime)
	}
}

// ETag 不含 server_time：同输入不同 now → ETag 稳定。
func TestBootstrap_ETagStableAcrossTime(t *testing.T) {
	s := newBootstrap()
	_, e1 := s.Build("stable", "1.0.0", "darwin-arm64", time.Unix(1000, 0))
	_, e2 := s.Build("stable", "1.0.0", "darwin-arm64", time.Unix(9999, 0))
	if e1 != e2 {
		t.Errorf("ETag 不应随 server_time 变化: %s vs %s", e1, e2)
	}
	if e1 == "" || e1[0] != '"' {
		t.Errorf("ETag 应为带引号强 ETag, 实际 %q", e1)
	}
}

// ETag 分桶：channel/version/platform 任一不同 → ETag 不同。
func TestBootstrap_ETagBucketing(t *testing.T) {
	s := newBootstrap()
	base := mustETag(s, "stable", "1.0.0", "darwin-arm64")
	cases := map[string]string{
		"channel":  mustETag(s, "beta", "1.0.0", "darwin-arm64"),
		"version":  mustETag(s, "stable", "1.1.0", "darwin-arm64"),
		"platform": mustETag(s, "stable", "1.0.0", "win32-x64"),
	}
	for dim, et := range cases {
		if et == base {
			t.Errorf("切换 %s 维度 ETag 应不同, 却与基准相同", dim)
		}
	}
}

// ETag 随内容变化：flags 变更（mcp_enabled）→ ETag 改变。
func TestBootstrap_ETagChangesWithContent(t *testing.T) {
	off := service.NewBootstrapService("1.4.2", "1.2.0", false, 25, nil, nil)
	on := service.NewBootstrapService("1.4.2", "1.2.0", true, 25, nil, nil)
	if mustETag(off, "stable", "1.0.0", "darwin-arm64") == mustETag(on, "stable", "1.0.0", "darwin-arm64") {
		t.Error("flags 变更后 ETag 应改变")
	}
}

// notices 窗口过滤：未到 starts_at / 已过 ends_at 不返；窗口内返回。空时为非 nil [].
func TestBootstrap_NoticesWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	notices := []service.Notice{
		{ID: "active", Level: "info", Title: "t", Content: "c"},                                // 无边界 → 始终展示
		{ID: "future", Level: "info", Title: "t", Content: "c", StartsAt: 2000},                // 未到
		{ID: "past", Level: "info", Title: "t", Content: "c", EndsAt: 500},                     // 已过
		{ID: "inwindow", Level: "info", Title: "t", Content: "c", StartsAt: 900, EndsAt: 1100}, // 窗口内
	}
	s := newBootstrap(notices...)
	resp, _ := s.Build("stable", "1.0.0", "darwin-arm64", now)

	got := map[string]bool{}
	for _, n := range resp.Notices {
		got[n.ID] = true
	}
	if !got["active"] || !got["inwindow"] {
		t.Errorf("窗口内公告应展示, 实际 %v", got)
	}
	if got["future"] || got["past"] {
		t.Errorf("窗口外公告不应展示, 实际 %v", got)
	}

	// 空公告 → 非 nil 切片。
	empty, _ := newBootstrap().Build("stable", "1.0.0", "darwin-arm64", now)
	if empty.Notices == nil {
		t.Error("空公告应为非 nil []")
	}
}

func mustETag(s *service.BootstrapService, channel, version, platform string) string {
	_, et := s.Build(channel, version, platform, time.Unix(1000, 0))
	return et
}
