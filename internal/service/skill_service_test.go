package service_test

import (
	"context"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeSkills 是 clawhub.SkillsClient 的内存 fake。
type fakeSkills struct {
	page     *clawhub.SkillPage
	detail   *clawhub.SkillDetail
	versions *clawhub.SkillVersionPage
	version  *clawhub.SkillVersionDetail
	resolve  *clawhub.ResolveResult
	download *clawhub.DownloadTarget
	gotHash  string
	err      error
}

func (f *fakeSkills) ListSkills(_ context.Context, _ clawhub.SkillListParams) (*clawhub.SkillPage, error) {
	return f.page, f.err
}
func (f *fakeSkills) GetSkill(_ context.Context, _ string) (*clawhub.SkillDetail, error) {
	return f.detail, f.err
}
func (f *fakeSkills) ListSkillVersions(_ context.Context, _ string, _ clawhub.PageParams) (*clawhub.SkillVersionPage, error) {
	return f.versions, f.err
}
func (f *fakeSkills) GetSkillVersion(_ context.Context, _, _ string) (*clawhub.SkillVersionDetail, error) {
	return f.version, f.err
}
func (f *fakeSkills) ResolveSkill(_ context.Context, _, hash string) (*clawhub.ResolveResult, error) {
	f.gotHash = hash
	return f.resolve, f.err
}
func (f *fakeSkills) SkillDownloadURL(_ context.Context, _, _ string) (*clawhub.DownloadTarget, error) {
	return f.download, f.err
}

// 列表翻译 + X-Platform 平台过滤（metadata.systems）。
func TestListSkills_TranslatesAndFilters(t *testing.T) {
	fake := &fakeSkills{
		page: &clawhub.SkillPage{
			Items: []clawhub.SkillListItem{
				{Slug: "mac-skill", DisplayName: "Mac", Category: &clawhub.Category{ID: "research", Label: "市场调研"}, Metadata: &clawhub.SkillMetadata{Systems: []string{"darwin-arm64"}}},
				{Slug: "win-skill", DisplayName: "Win", Metadata: &clawhub.SkillMetadata{Systems: []string{"win32-x64"}}},
				{Slug: "any-skill", DisplayName: "Any"},
			},
			NextCursor: nil,
		},
	}
	svc := service.NewSkillService(fake)

	page, err := svc.ListSkills(context.Background(), service.SkillListParams{}, service.CompatContext{Platform: "darwin-arm64"})
	if err != nil {
		t.Fatalf("ListSkills 失败: %v", err)
	}
	got := map[string]bool{}
	for _, it := range page.Items {
		got[it.Slug] = true
	}
	if !got["mac-skill"] || !got["any-skill"] {
		t.Errorf("应保留 mac-skill 与 any-skill, 实际 %v", got)
	}
	if got["win-skill"] {
		t.Error("win-skill 平台不匹配应被过滤")
	}
	// 分类翻译。
	for _, it := range page.Items {
		if it.Slug == "mac-skill" && (it.Category == nil || it.Category.ID != "research") {
			t.Errorf("category 翻译错误: %+v", it.Category)
		}
	}
}

// 详情翻译：category + latestVersion + metadata。
func TestGetSkill_Translates(t *testing.T) {
	fake := &fakeSkills{
		detail: &clawhub.SkillDetail{
			Skill:         clawhub.SkillInfo{Slug: "gifgrep", DisplayName: "GifGrep", Category: &clawhub.Category{ID: "research", Label: "市场调研"}, Tags: map[string]string{"latest": "1.2.0"}},
			LatestVersion: &clawhub.SkillVersionSummary{Version: "1.2.0", Changelog: "init", License: "MIT"},
			Metadata:      &clawhub.SkillMetadata{OS: []string{"darwin"}},
		},
	}
	svc := service.NewSkillService(fake)

	d, err := svc.GetSkill(context.Background(), "gifgrep")
	if err != nil {
		t.Fatalf("GetSkill 失败: %v", err)
	}
	if d.Skill.Category == nil || d.Skill.Category.ID != "research" {
		t.Errorf("category 翻译错误: %+v", d.Skill.Category)
	}
	if d.Skill.Tags["latest"] != "1.2.0" {
		t.Errorf("tags 透传错误: %+v", d.Skill.Tags)
	}
	if d.LatestVersion == nil || d.LatestVersion.License != "MIT" {
		t.Errorf("latestVersion 翻译错误: %+v", d.LatestVersion)
	}
}

// 版本详情翻译：artifact.sha256 + files。
func TestGetSkillVersion_Translates(t *testing.T) {
	fake := &fakeSkills{
		version: &clawhub.SkillVersionDetail{
			Skill: clawhub.SkillVersionSkill{Slug: "gifgrep", DisplayName: "GifGrep"},
			Version: clawhub.SkillVersion{
				Version:  "1.2.0",
				Files:    []clawhub.VersionFile{{Path: "SKILL.md", Size: 5, SHA256: "f1"}},
				Artifact: clawhub.SkillArtifact{SHA256: "archive-sha", Size: 1024},
			},
		},
	}
	svc := service.NewSkillService(fake)

	d, err := svc.GetSkillVersion(context.Background(), "gifgrep", "1.2.0")
	if err != nil {
		t.Fatalf("GetSkillVersion 失败: %v", err)
	}
	if d.Version.Artifact.SHA256 != "archive-sha" {
		t.Errorf("artifact.sha256 翻译错误: %q", d.Version.Artifact.SHA256)
	}
	if len(d.Version.Files) != 1 || d.Version.Files[0].SHA256 != "f1" {
		t.Errorf("files 翻译错误: %+v", d.Version.Files)
	}
}

// resolve 翻译：match/latestVersion，match==nil 透传供客户端辨因。
func TestResolveSkill_Translates(t *testing.T) {
	fake := &fakeSkills{
		resolve: &clawhub.ResolveResult{Slug: "gifgrep", Match: nil, LatestVersion: &clawhub.ResolveVersion{Version: "1.3.0"}},
	}
	svc := service.NewSkillService(fake)

	r, err := svc.ResolveSkill(context.Background(), "gifgrep", "deadbeef")
	if err != nil {
		t.Fatalf("ResolveSkill 失败: %v", err)
	}
	if fake.gotHash != "deadbeef" {
		t.Errorf("hash 未透传: %q", fake.gotHash)
	}
	if r.Match != nil {
		t.Errorf("match 应为 nil（本地被改动辨因），实际 %+v", r.Match)
	}
	if r.LatestVersion == nil || r.LatestVersion.Version != "1.3.0" {
		t.Errorf("latestVersion 翻译错误: %+v", r.LatestVersion)
	}
}

// 下载 URL：取回 ClawHub 签发地址。
func TestSkillDownloadURL(t *testing.T) {
	fake := &fakeSkills{download: &clawhub.DownloadTarget{URL: "https://r2.example.com/s.zip?sig=x"}}
	svc := service.NewSkillService(fake)

	url, err := svc.DownloadURL(context.Background(), "gifgrep", "")
	if err != nil {
		t.Fatalf("DownloadURL 失败: %v", err)
	}
	if url != "https://r2.example.com/s.zip?sig=x" {
		t.Errorf("下载 URL 错误: %q", url)
	}
}
