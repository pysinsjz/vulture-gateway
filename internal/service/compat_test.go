package service

import (
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2.0", "1.10.0", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.5", "1.5.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3-rc1", "1.2.3", 0},
		{"1.0.0", "1.0.1", -1},
		{"", "0.0.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, 期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompatiblePackage(t *testing.T) {
	item := clawhub.PackageListItem{HostTargets: []string{"darwin-arm64"}, MinAppVersion: "1.0.0"}

	if !compatiblePackage(item, CompatContext{}) {
		t.Error("空上下文不应过滤")
	}
	if !compatiblePackage(item, CompatContext{Platform: "darwin-arm64", AppVersion: "1.5.0"}) {
		t.Error("平台匹配 + app 版本满足应兼容")
	}
	if compatiblePackage(item, CompatContext{Platform: "win32-x64"}) {
		t.Error("平台不匹配应不兼容")
	}
	if compatiblePackage(item, CompatContext{AppVersion: "0.9.0"}) {
		t.Error("app 版本低于 minAppVersion 应不兼容")
	}

	noTargets := clawhub.PackageListItem{}
	if !compatiblePackage(noTargets, CompatContext{Platform: "darwin-arm64"}) {
		t.Error("hostTargets 为空表示不限平台，应兼容")
	}
}

func TestCompatibleSkill(t *testing.T) {
	if !compatibleSkill(nil, CompatContext{Platform: "darwin-arm64"}) {
		t.Error("无 metadata 不应过滤")
	}
	if !compatibleSkill(&clawhub.SkillMetadata{}, CompatContext{}) {
		t.Error("空 X-Platform 不应过滤")
	}

	bySystems := &clawhub.SkillMetadata{Systems: []string{"darwin-arm64"}}
	if !compatibleSkill(bySystems, CompatContext{Platform: "darwin-arm64"}) {
		t.Error("systems 匹配应兼容")
	}
	if compatibleSkill(bySystems, CompatContext{Platform: "win32-x64"}) {
		t.Error("systems 不匹配应不兼容")
	}

	byOS := &clawhub.SkillMetadata{OS: []string{"darwin"}}
	if !compatibleSkill(byOS, CompatContext{Platform: "darwin-arm64"}) {
		t.Error("os 段匹配（darwin-arm64→darwin）应兼容")
	}
	if compatibleSkill(byOS, CompatContext{Platform: "win32-x64"}) {
		t.Error("os 段不匹配应不兼容")
	}
}
