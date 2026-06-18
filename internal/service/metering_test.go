package service_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

func newMeter(t *testing.T, caps map[string]int64, pricing service.Pricing) (*service.MeteringService, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	windows := []service.UsageWindow{
		{Name: service.Window5h, Size: service.Window5hSize, Cap: caps[service.Window5h]},
		{Name: service.WindowWeek, Size: service.WindowWeekSize, Cap: caps[service.WindowWeek]},
	}
	return service.NewMeteringService(rdb, windows, pricing), mr
}

var flatPricing = service.Pricing{PromptCreditPerToken: 1, CompletionCreditPerToken: 1}

// 乐观放行：空窗预检放行；单请求扣减可使窗超出自身 Cap；之后预检触顶。
func TestMetering_OptimisticThenExceeded(t *testing.T) {
	m, _ := newMeter(t, map[string]int64{service.Window5h: 5}, flatPricing)
	ctx := context.Background()
	now := time.Now()

	// 空窗放行。
	pre, err := m.Precheck(ctx, "u1", now)
	if err != nil || pre.Exceeded {
		t.Fatalf("空窗应放行, exceeded=%v err=%v", pre.Exceeded, err)
	}

	// 单请求扣 15 Credit（> Cap 5）：乐观放行允许单请求超窗。
	if err := m.Record(ctx, "u1", litellm.Usage{PromptTokens: 12, CompletionTokens: 3, TotalTokens: 15}, now); err != nil {
		t.Fatalf("扣减失败: %v", err)
	}

	// 再预检：已触顶。
	pre, err = m.Precheck(ctx, "u1", now)
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if !pre.Exceeded {
		t.Fatal("扣减后应触顶")
	}
	if len(pre.Resets) != 1 || pre.Resets[0].Window != service.Window5h {
		t.Errorf("仅 5h 窗触顶, 实际 %+v", pre.Resets)
	}
	// 恢复时刻 = oldest(now) + 5h。
	wantReset := now.Unix() + int64(service.Window5hSize.Seconds())
	if pre.Resets[0].ResetUnix != wantReset {
		t.Errorf("reset = %d, 期望 %d", pre.Resets[0].ResetUnix, wantReset)
	}
	if pre.RetryAfter <= 0 {
		t.Errorf("RetryAfter 应为正, 实际 %d", pre.RetryAfter)
	}
}

// 滑动修剪：超过窗口的旧事件不计入求和。
func TestMetering_SlidesOutOldEvents(t *testing.T) {
	m, _ := newMeter(t, map[string]int64{service.Window5h: 5}, flatPricing)
	ctx := context.Background()
	now := time.Now()

	// 6h 前的一笔（早于 5h 窗）。
	old := now.Add(-6 * time.Hour)
	if err := m.Record(ctx, "u1", litellm.Usage{PromptTokens: 100, TotalTokens: 100}, old); err != nil {
		t.Fatalf("扣减失败: %v", err)
	}
	// 现在预检：旧事件已滑出，应未触顶。
	pre, err := m.Precheck(ctx, "u1", now)
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if pre.Exceeded {
		t.Error("旧事件应滑出窗口, 不应触顶")
	}
}

// 零 Credit（无 usage 硬错误）不写入窗口。
func TestMetering_ZeroCreditNotRecorded(t *testing.T) {
	m, _ := newMeter(t, map[string]int64{service.Window5h: 1}, flatPricing)
	ctx := context.Background()
	now := time.Now()
	if err := m.Record(ctx, "u1", litellm.Usage{}, now); err != nil {
		t.Fatalf("扣减失败: %v", err)
	}
	pre, _ := m.Precheck(ctx, "u1", now)
	if pre.Exceeded {
		t.Error("零 Credit 不应写入, 窗口应为空")
	}
}

// 并发原子性：N 个并发 Record 不丢；Cap=N*credits 时第 N+1 次预检恰触顶。
func TestMetering_ConcurrentDebitsNoLoss(t *testing.T) {
	const n = 20
	const perReq = 3 // 每次 usage 折算 3 Credit
	m, _ := newMeter(t, map[string]int64{service.Window5h: n * perReq}, flatPricing)
	ctx := context.Background()
	now := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Record(ctx, "u1", litellm.Usage{PromptTokens: perReq, TotalTokens: perReq}, now)
		}()
	}
	wg.Wait()

	// 累计应为 n*perReq，恰达 Cap → 触顶（证明无丢失）。
	pre, err := m.Precheck(ctx, "u1", now)
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if !pre.Exceeded {
		t.Errorf("%d 次并发扣减应使窗满 Cap, 出现丢失", n)
	}
}

// 定价折算：向上取整，非零用量至少计 1。
func TestPricing_CreditsFor(t *testing.T) {
	p := service.Pricing{PromptCreditPerToken: 0.001, CompletionCreditPerToken: 0.001}
	// 1 token * 0.001 = 0.001 → ceil 1（非零用量至少 1）。
	if got := p.CreditsFor(litellm.Usage{PromptTokens: 1, TotalTokens: 1}); got != 1 {
		t.Errorf("CreditsFor = %d, 期望 1", got)
	}
	// 完全无用量 → 0。
	if got := p.CreditsFor(litellm.Usage{}); got != 0 {
		t.Errorf("空 usage 应 0, 实际 %d", got)
	}
}

// 估算兜底：字符数÷4 向上取整。
func TestEstimateUsage(t *testing.T) {
	u := service.EstimateUsage(40, 8) // prompt 10, completion 2
	if u.PromptTokens != 10 || u.CompletionTokens != 2 || u.TotalTokens != 12 {
		t.Errorf("估算错误: %+v", u)
	}
	if u0 := service.EstimateUsage(0, 0); u0.TotalTokens != 0 {
		t.Errorf("零字符应 0 token, 实际 %+v", u0)
	}
}

// PromptChars：累加 message content 字符数。
func TestPromptChars(t *testing.T) {
	body := []byte(`{"model":"x","messages":[{"role":"user","content":"hello"},{"role":"user","content":"hi"}]}`)
	if got := service.PromptChars(body); got != len("hello")+len("hi") {
		t.Errorf("PromptChars = %d, 期望 %d", got, len("hello")+len("hi"))
	}
}
