package auth

import (
	"context"
	"testing"
	"time"
)

func newTestRateLimiter(t *testing.T) (*RateLimiter, *miniredisFF) {
	t.Helper()
	rdb, mr := testRedis(t)
	rl := NewRateLimiter(rdb, RateLimitConfig{
		LoginMaxFailures: 5,
		LoginLockWindow:  15 * time.Minute,
		SendMax:          3,
		SendWindow:       10 * time.Minute,
	})
	return rl, &miniredisFF{mr}
}

type miniredisFF struct{ mr interface{ FastForward(time.Duration) } }

func (h *miniredisFF) ff(d time.Duration) { h.mr.FastForward(d) }

func TestRateLimiter_LoginLockAfterMaxFailures(t *testing.T) {
	rl, _ := newTestRateLimiter(t)
	ctx := context.Background()
	const id, ip = "a@b.com", "1.2.3.4"

	for i := 0; i < 4; i++ {
		_ = rl.RecordLoginFailure(ctx, id, ip)
		if locked, _ := rl.IsLoginLocked(ctx, id, ip); locked {
			t.Fatalf("第 %d 次失败后不应锁定", i+1)
		}
	}
	// 第 5 次失败 → 锁定。
	_ = rl.RecordLoginFailure(ctx, id, ip)
	if locked, _ := rl.IsLoginLocked(ctx, id, ip); !locked {
		t.Error("5 次失败后应锁定")
	}
}

func TestRateLimiter_LoginResetUnlocks(t *testing.T) {
	rl, _ := newTestRateLimiter(t)
	ctx := context.Background()
	const id, ip = "a@b.com", "1.2.3.4"

	for i := 0; i < 5; i++ {
		_ = rl.RecordLoginFailure(ctx, id, ip)
	}
	if locked, _ := rl.IsLoginLocked(ctx, id, ip); !locked {
		t.Fatal("应已锁定")
	}
	// 成功登录后清零计数 → 解锁。
	if err := rl.ResetLogin(ctx, id, ip); err != nil {
		t.Fatalf("Reset 失败: %v", err)
	}
	if locked, _ := rl.IsLoginLocked(ctx, id, ip); locked {
		t.Error("Reset 后应解锁")
	}
}

func TestRateLimiter_LoginLockExpires(t *testing.T) {
	rl, h := newTestRateLimiter(t)
	ctx := context.Background()
	const id, ip = "a@b.com", "1.2.3.4"

	for i := 0; i < 5; i++ {
		_ = rl.RecordLoginFailure(ctx, id, ip)
	}
	if locked, _ := rl.IsLoginLocked(ctx, id, ip); !locked {
		t.Fatal("应已锁定")
	}
	h.ff(15*time.Minute + time.Second)
	if locked, _ := rl.IsLoginLocked(ctx, id, ip); locked {
		t.Error("锁定窗口过后应自动解锁")
	}
}

// 不同 IP 应独立计数（按 identifier + IP）。
func TestRateLimiter_LoginPerIPIsolated(t *testing.T) {
	rl, _ := newTestRateLimiter(t)
	ctx := context.Background()
	const id = "a@b.com"

	for i := 0; i < 5; i++ {
		_ = rl.RecordLoginFailure(ctx, id, "1.1.1.1")
	}
	if locked, _ := rl.IsLoginLocked(ctx, id, "2.2.2.2"); locked {
		t.Error("另一 IP 不应受影响")
	}
}

// 改密锁与登录锁应作用域隔离（ADR-0015）：一方触顶不应锁定另一方，
// 且一方成功清零不应解锁另一方——防交叉污染与「改密成功顺带解登录锁」。
func TestRateLimiter_ScopeIsolation(t *testing.T) {
	rl, _ := newTestRateLimiter(t)
	ctx := context.Background()
	const id, ip = "a@b.com", "1.2.3.4"

	// 登录侧打满锁定。
	for i := 0; i < 5; i++ {
		_ = rl.RecordFailure(ctx, ScopeLogin, id, ip)
	}
	if locked, _ := rl.IsLocked(ctx, ScopeLogin, id, ip); !locked {
		t.Fatal("login 作用域应已锁定")
	}
	// pwreset 作用域不应被登录失败连带锁定。
	if locked, _ := rl.IsLocked(ctx, ScopePasswordReset, id, ip); locked {
		t.Error("login 失败不应锁定 pwreset 作用域")
	}

	// 改密成功清零 pwreset 不应解锁 login。
	if err := rl.ResetFailures(ctx, ScopePasswordReset, id, ip); err != nil {
		t.Fatalf("ResetFailures 失败: %v", err)
	}
	if locked, _ := rl.IsLocked(ctx, ScopeLogin, id, ip); !locked {
		t.Error("清零 pwreset 不应解锁 login 作用域")
	}
}

func TestRateLimiter_SendQuota(t *testing.T) {
	rl, h := newTestRateLimiter(t)
	ctx := context.Background()
	const dest, ip = "a@b.com", "1.2.3.4"

	// 配额内（SendMax=3）应放行。
	for i := 0; i < 3; i++ {
		if ok, _ := rl.AllowSend(ctx, dest, ip); !ok {
			t.Fatalf("第 %d 次发送应放行", i+1)
		}
	}
	// 超配额拒绝。
	if ok, _ := rl.AllowSend(ctx, dest, ip); ok {
		t.Error("超过配额应拒绝")
	}
	// 过窗口后重置。
	h.ff(10*time.Minute + time.Second)
	if ok, _ := rl.AllowSend(ctx, dest, ip); !ok {
		t.Error("窗口过后应重新放行")
	}
}
