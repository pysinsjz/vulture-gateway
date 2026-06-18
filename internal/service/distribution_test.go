package service_test

import (
	"errors"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/service"
)

func fixtureReleases() []service.Release {
	return []service.Release{
		{Channel: "stable", Platform: "darwin-arm64", Version: "1.3.0", MinVersion: "1.0.0",
			DownloadURL: "https://r2.example.com/v1.3.0-arm64.dmg", Checksum: "sha256:aaa", Size: 100, ReleaseNotes: "stable arm"},
		{Channel: "stable", Platform: "win32-x64", Version: "1.3.0", MinVersion: "1.0.0",
			DownloadURL: "https://r2.example.com/v1.3.0-x64.exe", Checksum: "sha256:bbb", Size: 200},
		{Channel: "stable", Platform: "darwin-arm64", Version: "1.2.0", // 旧版本，应被 1.3.0 盖过
			DownloadURL: "https://r2.example.com/v1.2.0-arm64.dmg", Checksum: "sha256:old", Size: 90},
		{Channel: "beta", Platform: "darwin-arm64", Version: "1.4.0-beta", MinVersion: "1.0.0",
			DownloadURL: "https://r2.example.com/v1.4.0-beta-arm64.dmg", Checksum: "sha256:ccc", Size: 300},
	}
}

// 有新版本：current < latest → 完整摘要，选最高版本。
func TestDistribution_UpdateAvailable(t *testing.T) {
	s := service.NewDistributionService(fixtureReleases())
	res, err := s.Resolve("stable", "darwin-arm64", "1.2.0")
	if err != nil {
		t.Fatalf("Resolve 失败: %v", err)
	}
	if res.Update == nil {
		t.Fatal("应有更新")
	}
	if res.LatestVersion != "1.3.0" || res.Update.DownloadURL != "https://r2.example.com/v1.3.0-arm64.dmg" {
		t.Errorf("应选最高版本 1.3.0 的 arm 包, 实际 %+v", res.Update)
	}
	if res.Update.Mandatory {
		t.Error("1.2.0 >= min 1.0.0, 不应强更")
	}
}

// 已最新：current >= latest → Update nil。
func TestDistribution_UpToDate(t *testing.T) {
	s := service.NewDistributionService(fixtureReleases())
	res, err := s.Resolve("stable", "darwin-arm64", "1.3.0")
	if err != nil {
		t.Fatalf("Resolve 失败: %v", err)
	}
	if res.Update != nil {
		t.Errorf("current==latest 应无更新, 实际 %+v", res.Update)
	}
	if res.LatestVersion != "1.3.0" {
		t.Errorf("latest = %q, 期望 1.3.0", res.LatestVersion)
	}
	// 更高版本也算最新。
	if res2, _ := s.Resolve("stable", "darwin-arm64", "2.0.0"); res2.Update != nil {
		t.Error("current 高于 latest 也应无更新")
	}
}

// 平台选择：不同平台返回对应包，不串架构。
func TestDistribution_PlatformSelection(t *testing.T) {
	s := service.NewDistributionService(fixtureReleases())
	win, _ := s.Resolve("stable", "win32-x64", "1.0.0")
	if win.Update == nil || win.Update.Checksum != "sha256:bbb" {
		t.Errorf("win 平台应返回 win 包, 实际 %+v", win.Update)
	}
}

// 渠道隔离：stable 不选 beta 版本；beta 各自独立。
func TestDistribution_ChannelIsolation(t *testing.T) {
	s := service.NewDistributionService(fixtureReleases())
	stable, _ := s.Resolve("stable", "darwin-arm64", "1.0.0")
	if stable.LatestVersion != "1.3.0" {
		t.Errorf("stable 最新应为 1.3.0（不串 beta 1.4.0）, 实际 %q", stable.LatestVersion)
	}
	beta, _ := s.Resolve("beta", "darwin-arm64", "1.0.0")
	if beta.LatestVersion != "1.4.0-beta" {
		t.Errorf("beta 最新应为 1.4.0-beta, 实际 %q", beta.LatestVersion)
	}
}

// 强更：current < min_version → mandatory，即使发布未标 mandatory。
func TestDistribution_MandatoryByMinVersion(t *testing.T) {
	s := service.NewDistributionService([]service.Release{
		{Channel: "stable", Platform: "darwin-arm64", Version: "2.0.0", MinVersion: "1.5.0",
			DownloadURL: "u", Checksum: "sha256:x"},
	})
	res, _ := s.Resolve("stable", "darwin-arm64", "1.0.0") // < min 1.5.0
	if res.Update == nil || !res.Update.Mandatory {
		t.Errorf("低于 min 应强更提示, 实际 %+v", res.Update)
	}
}

// 无发布：ErrNoRelease。
func TestDistribution_NoRelease(t *testing.T) {
	s := service.NewDistributionService(fixtureReleases())
	if _, err := s.Resolve("stable", "darwin-x64", "1.0.0"); !errors.Is(err, service.ErrNoRelease) {
		t.Errorf("无匹配发布应 ErrNoRelease, 实际 %v", err)
	}
}

// 枚举校验。
func TestDistribution_Validators(t *testing.T) {
	if !service.IsValidPlatform("darwin-arm64") || service.IsValidPlatform("linux-x64") {
		t.Error("平台校验错误")
	}
	if !service.IsValidChannel("beta") || service.IsValidChannel("nightly") {
		t.Error("渠道校验错误")
	}
}
