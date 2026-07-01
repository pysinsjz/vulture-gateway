package clawhub

import (
	"context"
	"log"
	"time"
)

// Warmer 周期性地对 skill/plugin 列表发起「无过滤首页」请求，主动把结果推进
// cachingSkillsClient / cachingPackagesClient 的 Redis 缓存里，让桌面端的常规列表请求
// 命中缓存、不再等首个用户请求触发 fn() 穿透 ClawHub（见 cache.go cachedGet）。
//
// 范围：仅 ListSkills / ListPackages 两个列表端点的默认视图（无 cursor/sort/category），
// 即桌面端冷启动最常命中的组合；filter/category 组合空间无界，不纳入预热。
type Warmer struct {
	skills   SkillsClient
	packages PackagesClient
	interval time.Duration
}

// NewWarmer 构造预热器。interval<=0 时 Run 立即返回（禁用预热，如联调环境不需要）。
func NewWarmer(skills SkillsClient, packages PackagesClient, interval time.Duration) *Warmer {
	return &Warmer{skills: skills, packages: packages, interval: interval}
}

// Run 按 interval 周期预热，直到 ctx 被取消。首轮启动立即预热一次，此后每 tick 一次；
// 阻塞调用，预期由调用方 go 一个 goroutine 运行，随进程优雅停机的 ctx 一起结束。
func (w *Warmer) Run(ctx context.Context) {
	if w.interval <= 0 {
		return
	}

	w.warmOnce(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.warmOnce(ctx)
		}
	}
}

// warmOnce 预热一轮。单个端点失败只 WARN、不影响另一个、不中断循环——
// 与 cache.go 的 fail-open 原则一致：预热是锦上添花，不应拖垮或阻塞正常请求路径。
func (w *Warmer) warmOnce(ctx context.Context) {
	if _, err := w.skills.ListSkills(ctx, SkillListParams{}); err != nil {
		log.Printf("[clawhub-warmer] WARN 预热 skills 列表失败: %v", err)
	}
	if _, err := w.packages.ListPackages(ctx, ListParams{}); err != nil {
		log.Printf("[clawhub-warmer] WARN 预热 packages 列表失败: %v", err)
	}
}
