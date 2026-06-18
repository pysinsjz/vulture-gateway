package service

import "errors"

// 渠道与平台枚举（distribution.md / #27）。
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// validPlatforms 是受支持的平台枚举（X-Platform）。
var validPlatforms = map[string]struct{}{
	"darwin-arm64": {},
	"darwin-x64":   {},
	"win32-x64":    {},
}

// ErrNoRelease 表示该 (channel, platform) 暂无任何发布记录。
var ErrNoRelease = errors.New("distribution: 该平台/渠道暂无发布")

// Release 是一条发布记录（service 层视图，由 config 注入，#27）。
type Release struct {
	Channel      string
	Platform     string
	Version      string
	Mandatory    bool
	MinVersion   string
	DownloadURL  string
	Checksum     string
	Size         int64
	ReleaseNotes string
}

// AppUpdate 是「有新版本」的更新摘要（与 bootstrap app_update 同形态，#29 复用）。
type AppUpdate struct {
	LatestVersion string `json:"latest_version"`
	Mandatory     bool   `json:"mandatory"`
	DownloadURL   string `json:"download_url"`
	Checksum      string `json:"checksum"`
	Size          int64  `json:"size"`
	ReleaseNotes  string `json:"release_notes"`
}

// ResolveResult 是一次发布判定结果。Update=nil 表示已是最新（无更新）。
type ResolveResult struct {
	LatestVersion string
	Update        *AppUpdate
}

// DistributionService 实现宿主 App 自更新判定（#27）：按 (channel, platform) 解析最新发布、
// 与 current_version 比较给出更新摘要。判定逻辑供 app/latest（#27）与 bootstrap app_update（#29）共用。
type DistributionService struct {
	releases []Release
}

// NewDistributionService 构造服务，releases 为占位发布清单（config 注入）。
func NewDistributionService(releases []Release) *DistributionService {
	return &DistributionService{releases: releases}
}

// IsValidPlatform 判定平台枚举是否受支持。
func IsValidPlatform(platform string) bool {
	_, ok := validPlatforms[platform]
	return ok
}

// IsValidChannel 判定渠道是否合法。
func IsValidChannel(channel string) bool {
	return channel == ChannelStable || channel == ChannelBeta
}

// Resolve 解析 (channel, platform) 的最新发布并与 currentVersion 比较：
//   - 无任何匹配发布 → ErrNoRelease。
//   - current >= latest → ResolveResult{LatestVersion, Update:nil}（已最新）。
//   - current < latest → 带完整更新摘要；mandatory = 发布标记 或 current < min_version（仅提示）。
//
// 渠道隔离：只在同 channel 内选版本，stable/beta 互不串台。
func (s *DistributionService) Resolve(channel, platform, currentVersion string) (*ResolveResult, error) {
	var latest *Release
	for i := range s.releases {
		r := &s.releases[i]
		if r.Channel != channel || r.Platform != platform {
			continue
		}
		if latest == nil || compareVersions(r.Version, latest.Version) > 0 {
			latest = r
		}
	}
	if latest == nil {
		return nil, ErrNoRelease
	}

	res := &ResolveResult{LatestVersion: latest.Version}
	if compareVersions(currentVersion, latest.Version) >= 0 {
		return res, nil // 已最新
	}

	mandatory := latest.Mandatory
	if latest.MinVersion != "" && compareVersions(currentVersion, latest.MinVersion) < 0 {
		mandatory = true
	}
	res.Update = &AppUpdate{
		LatestVersion: latest.Version,
		Mandatory:     mandatory,
		DownloadURL:   latest.DownloadURL,
		Checksum:      latest.Checksum,
		Size:          latest.Size,
		ReleaseNotes:  latest.ReleaseNotes,
	}
	return res, nil
}
