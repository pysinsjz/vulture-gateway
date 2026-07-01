package service_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// warmerFakeSkills 是 clawhub.SkillsClient 的最小 fake（嵌入 fakeSkills 补全接口其余方法），
// 用调用计数验证 warmOnce 确实走到了列表 + 分类聚合两条路径。
type warmerFakeSkills struct {
	fakeSkills
	listCalls atomic.Int64
	dictErr   error
	listErr   error
}

func (f *warmerFakeSkills) ListSkills(ctx context.Context, p clawhub.SkillListParams) (*clawhub.SkillPage, error) {
	f.listCalls.Add(1)
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &clawhub.SkillPage{Items: []clawhub.SkillListItem{{Slug: "s"}}}, nil
}

func (f *warmerFakeSkills) ListSkillCategoriesDictionary(context.Context) ([]clawhub.CategoryDict, error) {
	if f.dictErr != nil {
		return nil, f.dictErr
	}
	return []clawhub.CategoryDict{{Slug: "other", Label: "其他"}}, nil
}

// warmerFakePackages 是 clawhub.PackagesClient 的最小 fake（嵌入 fakeClawHub），同上。
type warmerFakePackages struct {
	fakeClawHub
	listCalls atomic.Int64
	dictErr   error
	listErr   error
}

func (f *warmerFakePackages) ListPackages(ctx context.Context, p clawhub.ListParams) (*clawhub.PackagePage, error) {
	f.listCalls.Add(1)
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &clawhub.PackagePage{Items: []clawhub.PackageListItem{{Name: "p"}}}, nil
}

func (f *warmerFakePackages) ListPluginCategoriesDictionary(context.Context) ([]clawhub.CategoryDict, error) {
	if f.dictErr != nil {
		return nil, f.dictErr
	}
	return []clawhub.CategoryDict{{Slug: "other", Label: "其他"}}, nil
}

// runOnce 用一个已取消的 ctx 驱动 Run：Run 内部先无条件预热一轮，再进 for-select，已取消的
// ctx 让 select 立刻走 ctx.Done() 分支返回——等价于精确触发「恰好一轮 warmOnce」，
// 不依赖真实 sleep/ticker 时序，跑起来确定、不 flaky。
func runOnce(w *service.Warmer) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Run(ctx)
}

// 一轮预热应该调用「列表」和「分类聚合」两条 service 方法——分类聚合内部会再次调用
// ListSkills/ListPackages（分页），所以每轮 skills.listCalls/packages.listCalls 至少为 2
// （一次给 ListSkills/ListPlugins 本身，至少一次给分类聚合的分页循环）。
func TestWarmer_WarmsListAndCategories(t *testing.T) {
	skills := &warmerFakeSkills{}
	packages := &warmerFakePackages{}
	w := service.NewWarmer(service.NewSkillService(skills), service.NewPluginService(packages), time.Hour)

	runOnce(w)

	if got := skills.listCalls.Load(); got < 2 {
		t.Errorf("skills.ListSkills 调用次数 = %d, 期望至少 2（列表 + 分类聚合）", got)
	}
	if got := packages.listCalls.Load(); got < 2 {
		t.Errorf("packages.ListPackages 调用次数 = %d, 期望至少 2（列表 + 分类聚合）", got)
	}
}

// fail-open：某个端点报错（含分类字典报错）不影响其余端点被调用，也不 panic。
func TestWarmer_FailOpenOnError(t *testing.T) {
	skills := &warmerFakeSkills{listErr: errors.New("boom")}
	packages := &warmerFakePackages{dictErr: errors.New("boom")}
	w := service.NewWarmer(service.NewSkillService(skills), service.NewPluginService(packages), time.Hour)

	runOnce(w)

	if got := skills.listCalls.Load(); got == 0 {
		t.Error("skills.ListSkills 应该仍被调用一次（即使随后分类聚合报错）")
	}
	if got := packages.listCalls.Load(); got == 0 {
		t.Error("packages.ListPackages 应该仍被调用一次（列表本身不受分类字典报错影响）")
	}
}

// interval<=0 视为禁用：Run 立即返回，不发起任何预热调用。
func TestWarmer_RunDisabledWhenIntervalNonPositive(t *testing.T) {
	skills := &warmerFakeSkills{}
	packages := &warmerFakePackages{}
	w := service.NewWarmer(service.NewSkillService(skills), service.NewPluginService(packages), 0)

	done := make(chan struct{})
	go func() {
		w.Run(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("interval<=0 时 Run 应立即返回，但阻塞了")
	}

	if got := skills.listCalls.Load(); got != 0 {
		t.Errorf("skills.ListSkills 调用次数 = %d, 期望 0", got)
	}
}

// Run 立即执行一轮预热（不等第一个 tick），随后按 interval 周期重复，直到 ctx 取消。
func TestWarmer_RunWarmsImmediatelyThenPeriodically(t *testing.T) {
	skills := &warmerFakeSkills{}
	packages := &warmerFakePackages{}
	w := service.NewWarmer(service.NewSkillService(skills), service.NewPluginService(packages), 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	// 每轮至少 2 次 ListSkills（列表 + 分类分页），首轮 + 至少一次 tick ⇒ 至少 4 次。
	if got := skills.listCalls.Load(); got < 4 {
		t.Errorf("skills.ListSkills 调用次数 = %d, 期望至少 4（至少两轮 x 每轮至少 2 次）", got)
	}
}
