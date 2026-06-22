package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/notify"
)

// fakeSender 记录最近一次发送的 dest/code 与调用次数。
type fakeSender struct {
	calls    int
	lastDest string
	lastCode string
}

func (f *fakeSender) SendCode(_ context.Context, dest, code string) error {
	f.calls++
	f.lastDest = dest
	f.lastCode = code
	return nil
}

func newOTPServiceFixture(t *testing.T) (*OTPService, *auth.OTPStore, *fakeSender, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	otp := auth.NewOTPStore(rdb, 5*time.Minute, 60*time.Second, 5)
	limiter := auth.NewRateLimiter(rdb, auth.RateLimitConfig{
		LoginMaxFailures: 5, LoginLockWindow: 15 * time.Minute, SendMax: 3, SendWindow: 10 * time.Minute,
	})
	sender := &fakeSender{}
	svc := NewOTPService(otp, limiter, map[string]notify.CodeSender{"email": sender})
	return svc, otp, sender, mr
}

func TestOTPService_SendSuccess(t *testing.T) {
	svc, otp, sender, _ := newOTPServiceFixture(t)
	ctx := context.Background()

	if err := svc.SendCode(ctx, "email", "a@b.com", "1.2.3.4"); err != nil {
		t.Fatalf("发送应成功: %v", err)
	}
	if sender.calls != 1 || sender.lastDest != "a@b.com" {
		t.Fatalf("应发送一次到 a@b.com, 实际 calls=%d dest=%q", sender.calls, sender.lastDest)
	}
	// 下发的码应可被校验通过（与 OTPStore 中一致）。
	if ok, _ := otp.Verify(ctx, "a@b.com", sender.lastCode); !ok {
		t.Error("发送的验证码应能在 OTPStore 校验通过")
	}
}

func TestOTPService_UnknownChannel(t *testing.T) {
	svc, _, _, _ := newOTPServiceFixture(t)
	if err := svc.SendCode(context.Background(), "sms", "13800000000", "1.2.3.4"); !errors.Is(err, ErrUnknownChannel) {
		t.Errorf("未配置渠道应 ErrUnknownChannel, got %v", err)
	}
}

func TestOTPService_ResendTooSoon(t *testing.T) {
	svc, _, sender, _ := newOTPServiceFixture(t)
	ctx := context.Background()

	if err := svc.SendCode(ctx, "email", "a@b.com", "1.2.3.4"); err != nil {
		t.Fatalf("首发应成功: %v", err)
	}
	if err := svc.SendCode(ctx, "email", "a@b.com", "1.2.3.4"); !errors.Is(err, ErrResendTooSoon) {
		t.Errorf("60s 内重发应 ErrResendTooSoon, got %v", err)
	}
	if sender.calls != 1 {
		t.Errorf("重发被拒不应再次发送, calls=%d", sender.calls)
	}
}

func TestOTPService_QuotaExceeded(t *testing.T) {
	svc, _, _, mr := newOTPServiceFixture(t)
	ctx := context.Background()

	// SendMax=3：过重发间隔后逐次发送，第 4 次应被配额拦截。
	for i := 0; i < 3; i++ {
		if err := svc.SendCode(ctx, "email", "a@b.com", "1.2.3.4"); err != nil {
			t.Fatalf("第 %d 次发送应成功: %v", i+1, err)
		}
		mr.FastForward(61 * time.Second) // 越过重发间隔，但仍在配额窗口内
	}
	if err := svc.SendCode(ctx, "email", "a@b.com", "1.2.3.4"); !errors.Is(err, ErrSendRateLimited) {
		t.Errorf("超配额应 ErrSendRateLimited, got %v", err)
	}
}
