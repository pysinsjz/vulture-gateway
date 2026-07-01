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
