package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeClawHub 是 clawhub.PackagesClient 的内存 fake，便于在不触网下单测翻译/过滤逻辑。
type fakeClawHub struct {
	gotParams  clawhub.ListParams
	page       *clawhub.PackagePage
	detail     *clawhub.PackageDetail
	release    *clawhub.PackageReleaseDetail
	download   *clawhub.DownloadTarget
	trust      *clawhub.PluginTrust
	gotVersion string
	err        error
}

func (f *fakeClawHub) ListPackages(_ context.Context, params clawhub.ListParams) (*clawhub.PackagePage, error) {
	f.gotParams = params
	return f.page, f.err
}

func (f *fakeClawHub) GetPackage(_ context.Context, _ string) (*clawhub.PackageDetail, error) {
	return f.detail, f.err
}

func (f *fakeClawHub) GetPackageRelease(_ context.Context, _, _ string) (*clawhub.PackageReleaseDetail, error) {
	return f.release, f.err
}

func (f *fakeClawHub) PackageDownloadURL(_ context.Context, _, version string) (*clawhub.DownloadTarget, error) {
	f.gotVersion = version
	return f.download, f.err
}

func (f *fakeClawHub) PackageArtifactURL(_ context.Context, _, version string) (*clawhub.DownloadTarget, error) {
	f.gotVersion = version
	return f.download, f.err
}

func (f *fakeClawHub) PackageSecurity(_ context.Context, _, _ string) (*clawhub.PluginTrust, error) {
	return f.trust, f.err
}

func boolPtr(b bool) *bool { return &b }

func strPtr(s string) *string { return &s }

// 翻译正路：pluginCategory → category，其余字段透传，分页游标保留，hostTargets/minAppVersion 被剥离。
func TestListPlugins_TranslatesPackages(t *testing.T) {
	fake := &fakeClawHub{
		page: &clawhub.PackagePage{
			Items: []clawhub.PackageListItem{
				{
					Name:           "@vulture/notion-sync",
					DisplayName:    "Notion Sync",
					Summary:        "同步 Notion",
					PluginCategory: &clawhub.Category{ID: "ecommerce", Label: "电商与市场"},
					Family:         "code-plugin",
					Channel:        "community",
					IsOfficial:     false,
					LatestVersion:  "0.4.1",
					CapabilityTags: []string{"executes-code"},
					ExecutesCode:   boolPtr(true),
					ScanStatus:     "clean",
					HostTargets:    []string{"darwin-arm64"},
					MinAppVersion:  "1.0.0",
				},
			},
			NextCursor: strPtr("cursor-2"),
		},
	}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPlugins(context.Background(), service.PluginListParams{Limit: 20, Sort: "trending", Category: "ecommerce"}, service.CompatContext{})
	if err != nil {
		t.Fatalf("ListPlugins 失败: %v", err)
	}

	if fake.gotParams.Limit != 20 || fake.gotParams.Sort != "trending" || fake.gotParams.Category != "ecommerce" {
		t.Errorf("透传参数错误: %+v", fake.gotParams)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items 数 = %d, 期望 1", len(page.Items))
	}
	item := page.Items[0]
	if item.Category == nil || item.Category.ID != "ecommerce" || item.Category.Label != "电商与市场" {
		t.Errorf("category 翻译错误: %+v", item.Category)
	}
	if item.Name != "@vulture/notion-sync" || item.LatestVersion != "0.4.1" || item.ScanStatus != "clean" {
		t.Errorf("字段透传错误: %+v", item)
	}
	if item.ExecutesCode == nil || !*item.ExecutesCode {
		t.Errorf("executesCode 透传错误: %v", item.ExecutesCode)
	}
	if page.NextCursor == nil || *page.NextCursor != "cursor-2" {
		t.Errorf("nextCursor 保留错误: %v", page.NextCursor)
	}
}

// 兼容过滤：X-Platform 不在 hostTargets / minAppVersion 高于 X-App-Version → 被过滤。
func TestListPlugins_CompatFilter(t *testing.T) {
	fake := &fakeClawHub{
		page: &clawhub.PackagePage{
			Items: []clawhub.PackageListItem{
				{Name: "mac-only", DisplayName: "Mac Only", HostTargets: []string{"darwin-arm64"}},
				{Name: "win-only", DisplayName: "Win Only", HostTargets: []string{"win32-x64"}},
				{Name: "any-platform", DisplayName: "Any"},
				{Name: "needs-new-app", DisplayName: "Needs New App", MinAppVersion: "2.0.0"},
			},
		},
	}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPlugins(context.Background(), service.PluginListParams{}, service.CompatContext{Platform: "darwin-arm64", AppVersion: "1.5.0"})
	if err != nil {
		t.Fatalf("ListPlugins 失败: %v", err)
	}

	got := map[string]bool{}
	for _, it := range page.Items {
		got[it.Name] = true
	}
	if !got["mac-only"] || !got["any-platform"] {
		t.Errorf("应保留 mac-only 与 any-platform, 实际 %v", got)
	}
	if got["win-only"] {
		t.Error("win-only 平台不匹配应被过滤")
	}
	if got["needs-new-app"] {
		t.Error("needs-new-app 的 minAppVersion 高于 X-App-Version 应被过滤")
	}
}

// 无分类的制品翻译为 category=null。
func TestListPlugins_NilCategory(t *testing.T) {
	fake := &fakeClawHub{
		page: &clawhub.PackagePage{
			Items: []clawhub.PackageListItem{{Name: "x", DisplayName: "X", PluginCategory: nil}},
		},
	}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPlugins(context.Background(), service.PluginListParams{}, service.CompatContext{})
	if err != nil {
		t.Fatalf("ListPlugins 失败: %v", err)
	}
	if page.Items[0].Category != nil {
		t.Errorf("无分类应为 nil, 实际 %+v", page.Items[0].Category)
	}
}

// ClawHub 错误原样上抛，由 handler 重映射。
func TestListPlugins_PropagatesError(t *testing.T) {
	hubErr := &clawhub.Error{Status: 503, Code: "unavailable"}
	fake := &fakeClawHub{err: hubErr}
	svc := service.NewPluginService(fake)

	_, err := svc.ListPlugins(context.Background(), service.PluginListParams{}, service.CompatContext{})
	if !errors.Is(err, hubErr) {
		t.Errorf("应原样上抛 ClawHub 错误, 实际 %v", err)
	}
}

// 详情翻译：pluginCategory → category，latestVersion + compatibility 整形。
func TestGetPlugin_Translates(t *testing.T) {
	fake := &fakeClawHub{
		detail: &clawhub.PackageDetail{
			Package:        clawhub.PackageInfo{Name: "@v/x", DisplayName: "X", Family: "code-plugin", Channel: "official", IsOfficial: true},
			PluginCategory: &clawhub.Category{ID: "marketing", Label: "营销与广告"},
			LatestVersion:  &clawhub.PackageVersionSummary{Version: "1.2.0", CreatedAt: 100, Changelog: "fix"},
			Compatibility:  &clawhub.Compatibility{MinAppVersion: "1.0.0", HostTargets: []string{"darwin-arm64"}},
		},
	}
	svc := service.NewPluginService(fake)

	d, err := svc.GetPlugin(context.Background(), "@v/x")
	if err != nil {
		t.Fatalf("GetPlugin 失败: %v", err)
	}
	if d.Package.Category == nil || d.Package.Category.ID != "marketing" {
		t.Errorf("category 翻译错误: %+v", d.Package.Category)
	}
	if d.LatestVersion == nil || d.LatestVersion.Version != "1.2.0" {
		t.Errorf("latestVersion 翻译错误: %+v", d.LatestVersion)
	}
	if d.Compatibility == nil || d.Compatibility.MinAppVersion != "1.0.0" {
		t.Errorf("compatibility 翻译错误: %+v", d.Compatibility)
	}
}

// 版本详情翻译：artifact + files + sha256 保留。
func TestGetPluginVersion_Translates(t *testing.T) {
	fake := &fakeClawHub{
		release: &clawhub.PackageReleaseDetail{
			Package: clawhub.PackageReleasePkg{Name: "@v/x", DisplayName: "X", Family: "code-plugin"},
			Version: clawhub.PackageRelease{
				Version:    "1.2.0",
				DistTags:   []string{"latest"},
				Files:      []clawhub.VersionFile{{Path: "index.js", Size: 10, SHA256: "abc"}},
				Artifact:   &clawhub.PackageArtifact{Kind: "npm-pack", SHA256: "deadbeef", Size: 2048},
				SHA256Hash: "fullhash",
			},
		},
	}
	svc := service.NewPluginService(fake)

	d, err := svc.GetPluginVersion(context.Background(), "@v/x", "1.2.0")
	if err != nil {
		t.Fatalf("GetPluginVersion 失败: %v", err)
	}
	if d.Version.Artifact == nil || d.Version.Artifact.Kind != "npm-pack" || d.Version.Artifact.SHA256 != "deadbeef" {
		t.Errorf("artifact 翻译错误: %+v", d.Version.Artifact)
	}
	if len(d.Version.Files) != 1 || d.Version.Files[0].SHA256 != "abc" {
		t.Errorf("files 翻译错误: %+v", d.Version.Files)
	}
	if d.Version.SHA256Hash != "fullhash" {
		t.Errorf("sha256hash 透传错误: %q", d.Version.SHA256Hash)
	}
}

// 下载 URL：取回 ClawHub 签发地址，version 透传。
func TestPluginDownloadURL(t *testing.T) {
	fake := &fakeClawHub{download: &clawhub.DownloadTarget{URL: "https://r2.example.com/x.zip?sig=abc"}}
	svc := service.NewPluginService(fake)

	url, err := svc.DownloadURL(context.Background(), "@v/x", "1.2.0")
	if err != nil {
		t.Fatalf("DownloadURL 失败: %v", err)
	}
	if url != "https://r2.example.com/x.zip?sig=abc" || fake.gotVersion != "1.2.0" {
		t.Errorf("下载 URL/version 错误: url=%q version=%q", url, fake.gotVersion)
	}

	artURL, err := svc.ArtifactURL(context.Background(), "@v/x", "1.2.0")
	if err != nil || artURL == "" {
		t.Errorf("ArtifactURL 失败: url=%q err=%v", artURL, err)
	}
}

// PluginTrust 翻译：blockedFromDownload + scanStatus + moderationState 透传。
func TestPluginSecurity_Translates(t *testing.T) {
	fake := &fakeClawHub{
		trust: &clawhub.PluginTrust{
			Package: clawhub.PluginTrustPkg{Name: "@v/x"},
			Release: clawhub.PluginTrustRelease{Version: "1.0.0", ArtifactSha256: "abc"},
			Trust: clawhub.PluginTrustBody{
				ScanStatus: "malicious", ModerationState: "quarantined",
				BlockedFromDownload: true, Reasons: []string{"scan:malicious"},
			},
		},
	}
	svc := service.NewPluginService(fake)

	trust, err := svc.PluginSecurity(context.Background(), "@v/x", "1.0.0")
	if err != nil {
		t.Fatalf("PluginSecurity 失败: %v", err)
	}
	if !trust.Trust.BlockedFromDownload || trust.Trust.ScanStatus != "malicious" || trust.Trust.ModerationState != "quarantined" {
		t.Errorf("trust 翻译错误: %+v", trust.Trust)
	}
	if trust.Release.ArtifactSha256 != "abc" || trust.Package.Name != "@v/x" {
		t.Errorf("package/release 翻译错误: %+v", trust)
	}
}

// 安全门阻断：ClawHub 返 403 → 原样上抛由 handler 透传。
func TestPluginDownloadURL_Blocked(t *testing.T) {
	hubErr := &clawhub.Error{Status: 403, Code: "blocked"}
	fake := &fakeClawHub{err: hubErr}
	svc := service.NewPluginService(fake)

	if _, err := svc.DownloadURL(context.Background(), "@v/x", ""); !errors.Is(err, hubErr) {
		t.Errorf("应上抛 403 阻断错误, 实际 %v", err)
	}
}
