package service

import (
	"context"
	"log"
	"time"
)

// warmSort 是桌面端发现页首次加载实际发出的 sort 值。桌面端「发现页固定按 downloads
// 排序，不再暴露排序选择」（见 vulture 仓库 apps/frontend/.../HubMarketView.tsx 的
// defaultSortFor），无 cursor/category——预热必须复现这个精确 query，否则缓存 key
// 对不上（这正是 2026-07-01 的一次事故：预热用了空 query，桌面端真实请求是
// ?sort=downloads，两个不同 key，预热白跑）。
//
// 这是一处跨仓库耦合：桌面端改排序默认值时，这里要跟着改，否则预热重新失焦。
const warmSort = "downloads"

// Warmer 周期性地调用 SkillService/PluginService 上桌面端冷启动实际会打的那几个方法，
// 主动把结果推进底层 clawhub caching client 的 Redis 缓存里，让桌面端的常规请求命中
// 缓存、不再触发 fn() 穿透 ClawHub。
//
// 之所以驱动 service 层而不是直接摆弄 clawhub.SkillsClient/PackagesClient：桌面端冷启动
// 是并发拉「列表」+「分类」两个端点（HubMarketView.tsx），而分类端点内部会分页拉全量
// list（categoriesPageSize/categoriesMaxPages，见 plugin_service.go/skill_service.go）
// 产生一串 limit=100[&cursor=...] 的 key——这套分页逻辑只应该有一份实现。直接调用
// service 方法，保证预热用的就是生产代码本身，两边不可能再对不上。
//
// CompatContext 传零值：过滤发生在拿到 raw 响应之后（fetch-then-filter），不影响
// 下层 clawhub 缓存 key，预热不需要关心平台/版本。
type Warmer struct {
	skills   *SkillService
	plugins  *PluginService
	interval time.Duration
}

// NewWarmer 构造预热器。interval<=0 时 Run 立即返回（禁用预热，如联调环境不需要）。
func NewWarmer(skills *SkillService, plugins *PluginService, interval time.Duration) *Warmer {
	return &Warmer{skills: skills, plugins: plugins, interval: interval}
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

// warmOnce 预热一轮：skill/plugin 各自的列表 + 分类聚合，共四次调用。
// 单次调用失败只 WARN、不影响其余调用、不中断循环——与 cache.go 的 fail-open 原则一致：
// 预热是锦上添花，不应拖垮或阻塞正常请求路径。
func (w *Warmer) warmOnce(ctx context.Context) {
	var cc CompatContext

	if _, err := w.skills.ListSkills(ctx, SkillListParams{Sort: warmSort}, cc); err != nil {
		log.Printf("[warmer] WARN 预热 skills 列表失败: %v", err)
	}
	if _, err := w.skills.SkillCategories(ctx, cc); err != nil {
		log.Printf("[warmer] WARN 预热 skills 分类失败: %v", err)
	}
	if _, err := w.plugins.ListPlugins(ctx, PluginListParams{Sort: warmSort}, cc); err != nil {
		log.Printf("[warmer] WARN 预热 plugins 列表失败: %v", err)
	}
	if _, err := w.plugins.PluginCategories(ctx, cc); err != nil {
		log.Printf("[warmer] WARN 预热 plugins 分类失败: %v", err)
	}
}
