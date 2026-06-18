package service

import (
	"strconv"
	"strings"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// CompatContext 是兼容过滤上下文，来自请求头 X-Platform / X-App-Version（§3.7）。
// 空字段表示该维度不参与过滤（客户端未携带对应头）。
type CompatContext struct {
	Platform   string // 如 darwin-arm64 / win32-x64
	AppVersion string // 桌面 App 版本（semver）
}

// compatiblePackage 判定一个 plugin 列表项是否与当前客户端兼容（fetch-then-filter）。
//   - 平台：item.HostTargets 非空且不含 Platform ⇒ 不兼容（HostTargets 为空表示不限平台）。
//   - App 版本：item.MinAppVersion 高于当前 AppVersion ⇒ 不兼容。
func compatiblePackage(item clawhub.PackageListItem, cc CompatContext) bool {
	if cc.Platform != "" && len(item.HostTargets) > 0 && !contains(item.HostTargets, cc.Platform) {
		return false
	}
	if cc.AppVersion != "" && item.MinAppVersion != "" && compareVersions(cc.AppVersion, item.MinAppVersion) < 0 {
		return false
	}
	return true
}

// compatibleSkill 判定一个 skill 是否与当前平台兼容（按 metadata.systems/os，§3.7）。
// 无 metadata 或未携带 X-Platform 时不过滤；systems 更精确，优先按其判定，否则退回 os 粗粒度。
func compatibleSkill(meta *clawhub.SkillMetadata, cc CompatContext) bool {
	if cc.Platform == "" || meta == nil {
		return true
	}
	if len(meta.Systems) > 0 {
		return contains(meta.Systems, cc.Platform)
	}
	if len(meta.OS) > 0 {
		return contains(meta.OS, osPart(cc.Platform))
	}
	return true
}

// osPart 取平台枚举的 OS 段（darwin-arm64 → darwin）。
func osPart(platform string) string {
	if i := strings.IndexByte(platform, '-'); i >= 0 {
		return platform[:i]
	}
	return platform
}

func contains(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

// compareVersions 比较两个点分版本号，返回 -1/0/1（a<b / a==b / a>b）。
// 容忍前导 v 与 pre-release/build 后缀（- 或 + 之后忽略）；缺省段按 0 处理。
// 仅用于 minAppVersion 门禁的「足够好」比较，不做完整 SemVer 优先级语义。
func compareVersions(a, b string) int {
	as := versionParts(a)
	bs := versionParts(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// versionParts 把 "v1.2.3-rc1" 解析为 [1,2,3]（忽略 v 前缀与 - / + 之后的后缀）。
func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	segs := strings.Split(v, ".")
	out := make([]int, 0, len(segs))
	for _, s := range segs {
		n, err := strconv.Atoi(s)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}
