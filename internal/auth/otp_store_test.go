package auth

import (
	"context"
	"regexp"
	"testing"
	"time"
)

const (
	testOTPTTL    = 5 * time.Minute
	testOTPResend = 60 * time.Second
	testOTPMax    = 5
)

func newTestOTPStore(t *testing.T) (*OTPStore, *otpHarness) {
	t.Helper()
	rdb, mr := testRedis(t)
	return NewOTPStore(rdb, testOTPTTL, testOTPResend, testOTPMax, ""), &otpHarness{mr: mr}
}

type otpHarness struct{ mr interface{ FastForward(time.Duration) } }

func TestOTPStore_IssueFormat(t *testing.T) {
	store, _ := newTestOTPStore(t)
	code, err := store.Issue(context.Background(), "a@b.com")
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		t.Errorf("验证码应为 6 位数字, 实际 %q", code)
	}
}

func TestOTPStore_VerifyCorrectConsumes(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	code, _ := store.Issue(ctx, "dest")

	ok, err := store.Verify(ctx, "dest", code)
	if err != nil || !ok {
		t.Fatalf("正确码应通过, ok=%v err=%v", ok, err)
	}
	// 一次性：消费后再验证同码应失败。
	if ok, _ := store.Verify(ctx, "dest", code); ok {
		t.Error("验证码应一次性，消费后不可复用")
	}
}

func TestOTPStore_BypassCode(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewOTPStore(rdb, testOTPTTL, testOTPResend, testOTPMax, "111111")
	ctx := context.Background()

	// 未发码也能用万能码直接通过。
	if ok, err := store.Verify(ctx, "dest", "111111"); err != nil || !ok {
		t.Fatalf("万能码应直接通过, ok=%v err=%v", ok, err)
	}

	// 非万能码仍走常规校验：未发码 → 不通过。
	if ok, _ := store.Verify(ctx, "dest", "222222"); ok {
		t.Error("非万能码且无真实码应不通过")
	}

	// 已发真实码时，万能码仍通过且清理真实码（后续真实码不可再用）。
	real, _ := store.Issue(ctx, "dest2")
	if ok, _ := store.Verify(ctx, "dest2", "111111"); !ok {
		t.Error("有真实码时万能码也应通过")
	}
	if ok, _ := store.Verify(ctx, "dest2", real); ok {
		t.Error("万能码通过后应已清理真实码")
	}
}

func TestOTPStore_BypassDisabledWhenEmpty(t *testing.T) {
	store, _ := newTestOTPStore(t) // bypassCode=""
	ctx := context.Background()

	// 空 bypass 时，固定码 111111 不应有任何特殊待遇（未发码 → 不通过）。
	if ok, _ := store.Verify(ctx, "dest", "111111"); ok {
		t.Error("bypassCode 为空时 111111 不应被放行")
	}
}

func TestOTPStore_PurposeIsolation(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()

	// 为 login 用途下发码：必须只在 login 命名空间内可验，pwreset 命名空间查不到。
	loginCode, err := store.Issue(ctx, "a@b.com", PurposeLogin)
	if err != nil {
		t.Fatalf("login Issue 失败: %v", err)
	}
	if ok, _ := store.Verify(ctx, "a@b.com", loginCode, PurposePasswordReset); ok {
		t.Error("login 用途的码不应能用于 pwreset 校验（用途隔离）")
	}
	if ok, _ := store.Verify(ctx, "a@b.com", loginCode, PurposeLogin); !ok {
		t.Error("login 用途的码应能在 login 命名空间校验通过")
	}

	// 为 pwreset 用途下发码：同理，不可用于 login。
	resetCode, err := store.Issue(ctx, "a@b.com", PurposePasswordReset)
	if err != nil {
		t.Fatalf("pwreset Issue 失败: %v", err)
	}
	if ok, _ := store.Verify(ctx, "a@b.com", resetCode, PurposeLogin); ok {
		t.Error("pwreset 用途的码不应能用于 login 校验（用途隔离）")
	}
	if ok, _ := store.Verify(ctx, "a@b.com", resetCode, PurposePasswordReset); !ok {
		t.Error("pwreset 用途的码应能在 pwreset 命名空间校验通过")
	}
}

func TestOTPStore_PurposeIndependentResend(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()

	// login 下发置起其重发闸，但不应影响 pwreset 的重发判定（各用途独立）。
	if _, err := store.Issue(ctx, "a@b.com", PurposeLogin); err != nil {
		t.Fatalf("login Issue 失败: %v", err)
	}
	if can, _ := store.CanResend(ctx, "a@b.com", PurposeLogin); can {
		t.Error("login 刚发码，login 用途重发间隔内不应允许重发")
	}
	if can, _ := store.CanResend(ctx, "a@b.com", PurposePasswordReset); !can {
		t.Error("pwreset 用途重发闸应独立，未发码时应允许发送")
	}
}

func TestOTPStore_DefaultPurposeIsLogin(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()

	// 不显式传 purpose（向后兼容）应等价于 login：默认下发的码可用显式 login 校验。
	code, err := store.Issue(ctx, "a@b.com")
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if ok, _ := store.Verify(ctx, "a@b.com", code, PurposeLogin); !ok {
		t.Error("默认 purpose 应为 login：默认下发的码应能以显式 login 校验")
	}
}

func TestOTPStore_VerifyWrong(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	_, _ = store.Issue(ctx, "dest")

	if ok, _ := store.Verify(ctx, "dest", "000000"); ok {
		t.Error("错误码应不通过")
	}
}

func TestOTPStore_MaxAttemptsLocksCode(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	code, _ := store.Issue(ctx, "dest")

	for i := 0; i < testOTPMax; i++ {
		if ok, _ := store.Verify(ctx, "dest", "999999"); ok {
			t.Fatalf("第 %d 次错误码不应通过", i+1)
		}
	}
	// 超过最大尝试次数后，即便给出正确码也应失败（单码作废）。
	if ok, _ := store.Verify(ctx, "dest", code); ok {
		t.Error("超过最大尝试次数后正确码也应失败")
	}
}

func TestOTPStore_Expiry(t *testing.T) {
	store, h := newTestOTPStore(t)
	ctx := context.Background()
	code, _ := store.Issue(ctx, "dest")

	h.mr.FastForward(testOTPTTL + time.Second)

	if ok, _ := store.Verify(ctx, "dest", code); ok {
		t.Error("过期后正确码应失败")
	}
}

func TestOTPStore_ResendInterval(t *testing.T) {
	store, h := newTestOTPStore(t)
	ctx := context.Background()

	// 首发前可发。
	if can, _ := store.CanResend(ctx, "dest"); !can {
		t.Error("首发前应允许发送")
	}
	if _, err := store.Issue(ctx, "dest"); err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	// 间隔内不可重发。
	if can, _ := store.CanResend(ctx, "dest"); can {
		t.Error("60s 间隔内不应允许重发")
	}
	// 过间隔后可重发。
	h.mr.FastForward(testOTPResend + time.Second)
	if can, _ := store.CanResend(ctx, "dest"); !can {
		t.Error("超过间隔后应允许重发")
	}
}
