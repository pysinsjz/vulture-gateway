package router_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pysinsjz/vulture-gateway/config"
)

// withReleases 注入占位发布清单。
func withReleases(releases ...config.ReleaseEntry) func(*config.Configuration) {
	return func(cfg *config.Configuration) { cfg.Distribution.Releases = releases }
}

func sampleReleases() []config.ReleaseEntry {
	return []config.ReleaseEntry{
		{Channel: "stable", Platform: "darwin-arm64", Version: "1.3.0", MinVersion: "1.0.0",
			DownloadURL: "https://r2.example.com/v1.3.0-arm64.dmg", Checksum: "sha256:aaa", Size: 100},
		{Channel: "stable", Platform: "win32-x64", Version: "1.3.0", MinVersion: "1.0.0",
			DownloadURL: "https://r2.example.com/v1.3.0-x64.exe", Checksum: "sha256:bbb", Size: 200},
		{Channel: "beta", Platform: "darwin-arm64", Version: "1.4.0", MinVersion: "1.0.0",
			DownloadURL: "https://r2.example.com/v1.4.0-arm64.dmg", Checksum: "sha256:ccc", Size: 300},
	}
}

func getAppLatest(t *testing.T, e http.Handler, query string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/latest"+query, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

type appLatestBody struct {
	UpdateAvailable bool   `json:"update_available"`
	LatestVersion   string `json:"latest_version"`
	Mandatory       bool   `json:"mandatory"`
	DownloadURL     string `json:"download_url"`
	Checksum        string `json:"checksum"`
	Size            int64  `json:"size"`
}

// 公开访问：无 Bearer → 200（公开例外）。
func TestAppLatest_PublicNoBearer(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))
	rec := getAppLatest(t, e, "?platform=darwin-arm64&current_version=1.0.0", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("公开端点应 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

// 有更新：返回完整摘要，checksum 形如 sha256:，download_url 指向 R2。
func TestAppLatest_UpdateAvailable(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))
	rec := getAppLatest(t, e, "?platform=darwin-arm64&current_version=1.1.0", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", rec.Code)
	}
	var b appLatestBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if !b.UpdateAvailable || b.LatestVersion != "1.3.0" {
		t.Errorf("应有更新到 1.3.0, 实际 %+v", b)
	}
	if !strings.HasPrefix(b.Checksum, "sha256:") {
		t.Errorf("checksum 应为 sha256: 形态, 实际 %q", b.Checksum)
	}
	if !strings.HasPrefix(b.DownloadURL, "https://r2.") {
		t.Errorf("download_url 应指向 R2, 实际 %q", b.DownloadURL)
	}
}

// 平台精确：X-Platform 选对应架构，不推错包。
func TestAppLatest_PlatformMatch(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))
	// query 缺省，回退 X-Platform 头。
	rec := getAppLatest(t, e, "?current_version=1.0.0", map[string]string{"X-Platform": "win32-x64"})
	var b appLatestBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.Checksum != "sha256:bbb" {
		t.Errorf("win32 应返回 win 包(sha256:bbb), 实际 %+v", b)
	}
}

// 渠道隔离 + 缺省 stable：不带 channel 走 stable（1.3.0），beta 独立（1.4.0）。
func TestAppLatest_ChannelIsolationAndDefault(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))

	def := getAppLatest(t, e, "?platform=darwin-arm64&current_version=1.0.0", nil)
	var bd appLatestBody
	_ = json.Unmarshal(def.Body.Bytes(), &bd)
	if bd.LatestVersion != "1.3.0" {
		t.Errorf("缺省渠道应 stable 1.3.0, 实际 %q", bd.LatestVersion)
	}

	beta := getAppLatest(t, e, "?platform=darwin-arm64&channel=beta&current_version=1.0.0", nil)
	var bb appLatestBody
	_ = json.Unmarshal(beta.Body.Bytes(), &bb)
	if bb.LatestVersion != "1.4.0" {
		t.Errorf("beta 渠道应 1.4.0, 实际 %q", bb.LatestVersion)
	}
}

// 已最新：current >= latest → update_available=false。
func TestAppLatest_UpToDate(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))
	rec := getAppLatest(t, e, "?platform=darwin-arm64&current_version=1.3.0", nil)
	var b appLatestBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.UpdateAvailable {
		t.Errorf("current==latest 应无更新, 实际 %+v", b)
	}
	if b.LatestVersion != "1.3.0" {
		t.Errorf("仍应回报 latest_version=1.3.0, 实际 %q", b.LatestVersion)
	}
}

// 强更提示：低于 min_version 标 mandatory，但仍为 200（不做版本硬门禁）。
func TestAppLatest_MandatoryNoHardGate(t *testing.T) {
	releases := []config.ReleaseEntry{
		{Channel: "stable", Platform: "darwin-arm64", Version: "2.0.0", MinVersion: "1.5.0",
			DownloadURL: "https://r2.example.com/v2.dmg", Checksum: "sha256:x", Size: 1},
	}
	e := newTestEngine(t, withReleases(releases...))
	rec := getAppLatest(t, e, "?platform=darwin-arm64&current_version=1.0.0", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("强更仅提示, 不应硬门禁, 期望 200 实际 %d", rec.Code)
	}
	var b appLatestBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if !b.Mandatory {
		t.Error("低于 min 应标 mandatory=true")
	}
}

// 参数错误：缺 platform / 非法 platform / 缺 current_version / 非法 channel → 400 ApiError。
func TestAppLatest_BadRequests(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))
	cases := []string{
		"?current_version=1.0.0",                                       // 缺 platform
		"?platform=linux-x64&current_version=1.0.0",                    // 非法 platform
		"?platform=darwin-arm64",                                       // 缺 current_version
		"?platform=darwin-arm64&channel=nightly&current_version=1.0.0", // 非法 channel
	}
	for _, q := range cases {
		rec := getAppLatest(t, e, q, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 应 400, 实际 %d", q, rec.Code)
		}
		assertApiError(t, rec)
	}
}

// 平台有效但无该平台发布 → 404 ApiError（不静默下发错包）。
func TestAppLatest_NoReleaseForPlatform(t *testing.T) {
	e := newTestEngine(t, withReleases(sampleReleases()...))
	rec := getAppLatest(t, e, "?platform=darwin-x64&current_version=1.0.0", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("无该平台发布应 404, 实际 %d", rec.Code)
	}
	assertApiError(t, rec)
}
