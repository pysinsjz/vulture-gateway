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
	gotParams       clawhub.ListParams
	gotVersionsPage clawhub.PageParams
	gotVersionsName string
	page            *clawhub.PackagePage
	detail          *clawhub.PackageDetail
	release         *clawhub.PackageReleaseDetail
	releasesPage    *clawhub.PackageReleasePage
	trust           *clawhub.PluginTrust
	gotVersion      string
	err             error
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

func (f *fakeClawHub) ListPackageReleases(_ context.Context, name string, page clawhub.PageParams) (*clawhub.PackageReleasePage, error) {
	f.gotVersionsName = name
	f.gotVersionsPage = page
	return f.releasesPage, f.err
}

func (f *fakeClawHub) PackageDownloadStreamURL(name, version string) string {
	f.gotVersion = version
	u := "http://clawhub.internal:3211/api/v1/packages/" + name + "/download"
	if version != "" {
		u += "?version=" + version
	}
	return u
}

func (f *fakeClawHub) PackageArtifactStreamURL(name, version string) string {
	f.gotVersion = version
	return "http://clawhub.internal:3211/api/v1/packages/" + name + "/versions/" + version + "/artifact/download"
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

// pagedPackages 是按调用次序逐页返回的 PackagesClient fake（验证 PluginCategories 的游标翻页聚合）。
// 嵌入 *fakeClawHub 复用其余接口方法，仅覆写 ListPackages。
type pagedPackages struct {
	*fakeClawHub
	pages []*clawhub.PackagePage
	calls int
}

func (f *pagedPackages) ListPackages(_ context.Context, _ clawhub.ListParams) (*clawhub.PackagePage, error) {
	if f.calls >= len(f.pages) {
		return &clawhub.PackagePage{}, nil
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

// PluginCategories 派生聚合：游标翻全量 + X-Platform 兼容过滤 + 首现序 + nil→「其他」末位 + 计数。
func TestPluginCategories_DerivesGroupedCounts(t *testing.T) {
	fake := &pagedPackages{
		fakeClawHub: &fakeClawHub{},
		pages: []*clawhub.PackagePage{
			{Items: []clawhub.PackageListItem{
				{Name: "@v/a", PluginCategory: &clawhub.Category{ID: "ecommerce", Label: "电商与市场"}},
				{Name: "@v/b", PluginCategory: &clawhub.Category{ID: "marketing", Label: "营销与广告"}, HostTargets: []string{"win32-x64"}}, // 平台过滤掉
				{Name: "@v/c", PluginCategory: &clawhub.Category{ID: "ecommerce", Label: "电商与市场"}, HostTargets: []string{"darwin-arm64"}},
			}, NextCursor: strPtr("c2")},
			{Items: []clawhub.PackageListItem{
				{Name: "@v/d", PluginCategory: &clawhub.Category{ID: "marketing", Label: "营销与广告"}},
				{Name: "@v/e"}, // pluginCategory==nil → 「其他」
			}, NextCursor: nil},
		},
	}
	svc := service.NewPluginService(fake)

	res, err := svc.PluginCategories(context.Background(), service.CompatContext{Platform: "darwin-arm64"})
	if err != nil {
		t.Fatalf("PluginCategories 失败: %v", err)
	}
	if fake.calls != 2 {
		t.Errorf("应翻完 2 页, 实际调用 %d 次", fake.calls)
	}
	want := []service.CategoryCount{
		{ID: "ecommerce", Label: "电商与市场", Count: 2}, // a + c
		{ID: "marketing", Label: "营销与广告", Count: 1},  // 仅 d（b 被平台过滤），首现序在 ecommerce 之后
		{ID: "other", Label: "其他", Count: 1},        // e，末位
	}
	if len(res.Categories) != len(want) {
		t.Fatalf("分类数 = %d, 期望 %d: %+v", len(res.Categories), len(want), res.Categories)
	}
	for i, w := range want {
		if res.Categories[i] != w {
			t.Errorf("第 %d 项 = %+v, 期望 %+v", i, res.Categories[i], w)
		}
	}
}

// 错误传播：上游列表报错时直接上抛。
func TestPluginCategories_PropagatesError(t *testing.T) {
	hubErr := &clawhub.Error{Status: 503, Code: "unavailable"}
	svc := service.NewPluginService(&fakeClawHub{err: hubErr})
	if _, err := svc.PluginCategories(context.Background(), service.CompatContext{}); !errors.Is(err, hubErr) {
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

// 版本历史翻译：透传 version/createdAt/changelog/distTags + 游标。
func TestListPluginVersions_Translates(t *testing.T) {
	cursor := "cur-2"
	fake := &fakeClawHub{
		releasesPage: &clawhub.PackageReleasePage{
			Items: []clawhub.PackageReleaseHistory{
				{Version: "0.1.0", CreatedAt: 100, Changelog: "init", DistTags: []string{"latest"}},
				{Version: "0.0.9", CreatedAt: 50, Changelog: "preview"},
			},
			NextCursor: &cursor,
		},
	}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPluginVersions(
		context.Background(), "@v/x",
		service.PageParams{Limit: 25, Cursor: "cur-1"},
	)
	if err != nil {
		t.Fatalf("ListPluginVersions 失败: %v", err)
	}
	if fake.gotVersionsName != "@v/x" {
		t.Errorf("name 透传错误: %q", fake.gotVersionsName)
	}
	if fake.gotVersionsPage.Limit != 25 || fake.gotVersionsPage.Cursor != "cur-1" {
		t.Errorf("分页参数透传错误: %+v", fake.gotVersionsPage)
	}
	if len(page.Items) != 2 {
		t.Fatalf("items 数量错误: %d", len(page.Items))
	}
	if page.Items[0].Version != "0.1.0" || page.Items[0].CreatedAt != 100 ||
		page.Items[0].Changelog != "init" || len(page.Items[0].DistTags) != 1 ||
		page.Items[0].DistTags[0] != "latest" {
		t.Errorf("第一项翻译错误: %+v", page.Items[0])
	}
	if page.Items[1].DistTags != nil {
		t.Errorf("无 distTags 时应保持空, 实际 %+v", page.Items[1].DistTags)
	}
	if page.NextCursor == nil || *page.NextCursor != "cur-2" {
		t.Errorf("游标透传错误: %+v", page.NextCursor)
	}
}

// 错误传播：上游版本历史报错时直接上抛。
func TestListPluginVersions_PropagatesError(t *testing.T) {
	hubErr := &clawhub.Error{Status: 503, Code: "unavailable"}
	svc := service.NewPluginService(&fakeClawHub{err: hubErr})
	if _, err := svc.ListPluginVersions(context.Background(), "@v/x", service.PageParams{}); !errors.Is(err, hubErr) {
		t.Errorf("应原样上抛 ClawHub 错误, 实际 %v", err)
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

// 流式下载 URL：legacy-zip 走 /packages/{name}/download?version=，npm-pack 走 /versions/{v}/artifact/download。
func TestPluginDownloadStreamURL(t *testing.T) {
	svc := service.NewPluginService(&fakeClawHub{})

	if got, want := svc.DownloadStreamURL("@v/x", "1.2.0"), "http://clawhub.internal:3211/api/v1/packages/@v/x/download?version=1.2.0"; got != want {
		t.Errorf("DownloadStreamURL = %q, 期望 %q", got, want)
	}
	if got, want := svc.ArtifactStreamURL("@v/x", "1.2.0"), "http://clawhub.internal:3211/api/v1/packages/@v/x/versions/1.2.0/artifact/download"; got != want {
		t.Errorf("ArtifactStreamURL = %q, 期望 %q", got, want)
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

