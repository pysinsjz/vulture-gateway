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
	return NewOTPStore(rdb, testOTPTTL, testOTPResend, testOTPMax), &otpHarness{mr: mr}
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
