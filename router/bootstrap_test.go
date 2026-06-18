package router_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pysinsjz/vulture-gateway/config"
)

func getBootstrap(t *testing.T, e http.Handler, query string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap"+query, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

var stdHeaders = map[string]string{"X-App-Version": "1.0.0", "X-Platform": "darwin-arm64"}

func withBootstrap(fn func(*config.BootstrapConfig)) func(*config.Configuration) {
	return func(cfg *config.Configuration) { fn(&cfg.Bootstrap) }
}

type bootstrapBody struct {
	ServerTime     int64            `json:"server_time"`
	GatewayVersion string           `json:"gateway_version"`
	AppUpdate      *json.RawMessage `json:"app_update"`
	FeatureFlags   map[string]any   `json:"feature_flags"`
	Notices        []map[string]any `json:"notices"`
}

// 公开访问 + 必填头齐全 → 200，含 server_time / feature_flags / notices / app_update:null。
func TestBootstrap_PublicHappyPath(t *testing.T) {
	e := newTestEngine(t)
	rec := getBootstrap(t, e, "", stdHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("应带 ETag 头")
	}
	var b bootstrapBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.ServerTime == 0 {
		t.Error("应有 server_time")
	}
	if b.AppUpdate != nil {
		t.Errorf("本切片 app_update 应为 null, 实际 %s", string(*b.AppUpdate))
	}
	if b.Notices == nil {
		t.Error("notices 应为 []（非 null）")
	}
}

// feature_flags 注册表：mcp_enabled(bool) + max_upload_mb(number 默认 25)，无注册表外键。
func TestBootstrap_FeatureFlags(t *testing.T) {
	e := newTestEngine(t)
	rec := getBootstrap(t, e, "", stdHeaders)
	var b bootstrapBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)

	if len(b.FeatureFlags) != 2 {
		t.Fatalf("应只发 2 个登记 flag, 实际 %v", b.FeatureFlags)
	}
	if v, ok := b.FeatureFlags["mcp_enabled"].(bool); !ok || v {
		t.Errorf("mcp_enabled 应 bool false, 实际 %v", b.FeatureFlags["mcp_enabled"])
	}
	// JSON number 解出为 float64。
	if v, ok := b.FeatureFlags["max_upload_mb"].(float64); !ok || v != 25 {
		t.Errorf("max_upload_mb 应为 number 25, 实际 %v", b.FeatureFlags["max_upload_mb"])
	}
}

// 带与不带 Bearer 内容一致（无用户态）。
func TestBootstrap_BearerIrrelevant(t *testing.T) {
	e := newTestEngine(t)
	noBearer := getBootstrap(t, e, "", stdHeaders)
	token := issueViaScaffold(t, e, "u", "d")
	h := map[string]string{"X-App-Version": "1.0.0", "X-Platform": "darwin-arm64", "Authorization": "Bearer " + token}
	withBearer := getBootstrap(t, e, "", h)
	if noBearer.Header().Get("ETag") != withBearer.Header().Get("ETag") {
		t.Error("带/不带 Bearer ETag 应一致（无用户态）")
	}
}

// 缺失必填头 → 400 ApiError。
func TestBootstrap_MissingHeaders400(t *testing.T) {
	e := newTestEngine(t)
	for _, h := range []map[string]string{
		{"X-Platform": "darwin-arm64"}, // 缺 X-App-Version
		{"X-App-Version": "1.0.0"},     // 缺 X-Platform
		{},                             // 都缺
	} {
		rec := getBootstrap(t, e, "", h)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("缺必填头应 400, 实际 %d", rec.Code)
		}
		assertApiError(t, rec)
	}
}

// 非法 channel → 400。
func TestBootstrap_InvalidChannel400(t *testing.T) {
	e := newTestEngine(t)
	rec := getBootstrap(t, e, "?channel=nightly", stdHeaders)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 channel 应 400, 实际 %d", rec.Code)
	}
	assertApiError(t, rec)
}

// If-None-Match：同桶同内容 → 304 空体。
func TestBootstrap_NotModified304(t *testing.T) {
	e := newTestEngine(t)
	first := getBootstrap(t, e, "", stdHeaders)
	etag := first.Header().Get("ETag")

	h := map[string]string{"X-App-Version": "1.0.0", "X-Platform": "darwin-arm64", "If-None-Match": etag}
	second := getBootstrap(t, e, "", h)
	if second.Code != http.StatusNotModified {
		t.Fatalf("同 ETag 应 304, 实际 %d", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 应空体, 实际 %q", second.Body.String())
	}
}

// 分桶隔离：切换平台维度，旧 ETag 不命中 304（得 200 新内容）。
func TestBootstrap_BucketIsolationNo304(t *testing.T) {
	e := newTestEngine(t)
	armEtag := getBootstrap(t, e, "", stdHeaders).Header().Get("ETag")

	// 拿 arm 的 ETag 去请求 win32 桶 → 不应命中 304。
	h := map[string]string{"X-App-Version": "1.0.0", "X-Platform": "win32-x64", "If-None-Match": armEtag}
	rec := getBootstrap(t, e, "", h)
	if rec.Code != http.StatusOK {
		t.Fatalf("跨桶旧 ETag 不应命中 304, 期望 200 实际 %d", rec.Code)
	}
	if rec.Header().Get("ETag") == armEtag {
		t.Error("不同桶 ETag 应不同")
	}
}

// 内容变更：notices 变化后 ETag 改变，旧 If-None-Match 得 200。
func TestBootstrap_ContentChangeInvalidatesETag(t *testing.T) {
	noNotice := newTestEngine(t)
	oldEtag := getBootstrap(t, noNotice, "", stdHeaders).Header().Get("ETag")

	withNotice := newTestEngine(t, withBootstrap(func(b *config.BootstrapConfig) {
		b.Notices = []config.NoticeEntry{{ID: "n1", Level: "info", Title: "t", Content: "c"}}
	}))
	h := map[string]string{"X-App-Version": "1.0.0", "X-Platform": "darwin-arm64", "If-None-Match": oldEtag}
	rec := getBootstrap(t, withNotice, "", h)
	if rec.Code != http.StatusOK {
		t.Fatalf("内容变更后旧 ETag 应得 200, 实际 %d", rec.Code)
	}
	var b bootstrapBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if len(b.Notices) != 1 {
		t.Errorf("应返回新公告, 实际 %v", b.Notices)
	}
}

// notices 窗口：过期公告不下发。
func TestBootstrap_ExpiredNoticeHidden(t *testing.T) {
	e := newTestEngine(t, withBootstrap(func(b *config.BootstrapConfig) {
		b.Notices = []config.NoticeEntry{
			{ID: "live", Level: "info", Title: "t", Content: "c"},
			{ID: "expired", Level: "info", Title: "t", Content: "c", EndsAt: 1}, // 1970 早已过期
		}
	}))
	rec := getBootstrap(t, e, "", stdHeaders)
	var b bootstrapBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	ids := map[string]bool{}
	for _, n := range b.Notices {
		ids[n["id"].(string)] = true
	}
	if !ids["live"] || ids["expired"] {
		t.Errorf("过期公告应被过滤, 实际 %v", ids)
	}
}
