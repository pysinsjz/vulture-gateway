package clawhub

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Run 立即执行一轮预热（不等第一个 tick），随后按 interval 周期重复，直到 ctx 取消。
func TestWarmer_RunWarmsImmediatelyThenPeriodically(t *testing.T) {
	skills := &fakeSkillsClient{}
	packages := &fakePackagesClient{}
	w := NewWarmer(skills, packages, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	if got := skills.listCalls.Load(); got < 2 {
		t.Errorf("skills.ListSkills 调用次数 = %d, 期望至少 2（首轮 + 至少一次 tick）", got)
	}
	if got := packages.listCalls.Load(); got < 2 {
		t.Errorf("packages.ListPackages 调用次数 = %d, 期望至少 2（首轮 + 至少一次 tick）", got)
	}
}

// interval<=0 视为禁用：Run 立即返回，不发起任何预热调用。
func TestWarmer_RunDisabledWhenIntervalNonPositive(t *testing.T) {
	skills := &fakeSkillsClient{}
	packages := &fakePackagesClient{}
	w := NewWarmer(skills, packages, 0)

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
	if got := packages.listCalls.Load(); got != 0 {
		t.Errorf("packages.ListPackages 调用次数 = %d, 期望 0", got)
	}
}

// fail-open：一个端点报错不影响另一个端点被调用，也不中断循环。
func TestWarmer_WarmOnceFailOpenOnError(t *testing.T) {
	skills := &erroringSkillsClient{fakeSkillsClient: fakeSkillsClient{}}
	packages := &fakePackagesClient{}
	w := NewWarmer(skills, packages, time.Hour)

	w.warmOnce(context.Background())

	if got := skills.listCalls.Load(); got != 1 {
		t.Errorf("skills.ListSkills 调用次数 = %d, 期望 1", got)
	}
	if got := packages.listCalls.Load(); got != 1 {
		t.Errorf("packages.ListPackages 调用次数 = %d, 期望 1（不应被 skills 的错误阻断）", got)
	}
}

// erroringSkillsClient 让 ListSkills 恒报错，其余方法沿用 fakeSkillsClient。
type erroringSkillsClient struct {
	fakeSkillsClient
}

func (f *erroringSkillsClient) ListSkills(ctx context.Context, p SkillListParams) (*SkillPage, error) {
	f.listCalls.Add(1)
	return nil, errors.New("boom")
}

// 回归测试：预热写入的 Redis key 必须与桌面端发现页首次加载的真实请求 key 一致
// （sort=downloads，无 cursor/category），否则预热是在给一个没人请求的 key 续热，
// 桌面端请求依旧会打穿 ClawHub——这正是本文件要防止再次发生的那个 bug。
func TestWarmer_PopulatesExactKeyDesktopRequests(t *testing.T) {
	rdb, mr := newTestCacheRDB(t)
	skills := NewCachingSkillsClient(&fakeSkillsClient{}, rdb, 5*time.Minute)
	packages := NewCachingPackagesClient(&fakePackagesClient{}, rdb, 5*time.Minute)
	w := NewWarmer(skills, packages, time.Hour)

	w.warmOnce(context.Background())

	keys := mr.Keys()
	want := map[string]bool{
		"gw:hub:skills?sort=downloads":   false,
		"gw:hub:packages?sort=downloads": false,
	}
	for _, k := range keys {
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("预热后 Redis 缺少 key %q（实际 keys=%v）", k, keys)
		}
	}
}
