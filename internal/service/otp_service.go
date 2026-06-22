package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/notify"
)

// 验证码下发的业务错误。
var (
	// ErrResendTooSoon 距上次发送未过重发间隔（60s）。
	ErrResendTooSoon = errors.New("发送过于频繁，请稍后再试")
	// ErrSendRateLimited 超过该 dest+IP 的发送配额（防轰炸）。
	ErrSendRateLimited = errors.New("发送次数过多，请稍后再试")
	// ErrUnknownChannel 渠道未配置。
	ErrUnknownChannel = errors.New("验证码渠道未配置")
)

// OTPService 编排验证码下发：重发间隔 + dest+IP 配额限流 → 生成码 → 经对应渠道发送。
type OTPService struct {
	otp     *auth.OTPStore
	limiter *auth.RateLimiter
	senders map[string]notify.CodeSender // channel(email/sms) -> sender
}

// NewOTPService 构造验证码服务。senders 按渠道名索引（email/sms）。
func NewOTPService(otp *auth.OTPStore, limiter *auth.RateLimiter, senders map[string]notify.CodeSender) *OTPService {
	return &OTPService{otp: otp, limiter: limiter, senders: senders}
}

// SendCode 向 dest 下发某渠道的验证码。先过重发间隔与配额限流，再生成并发送。
func (s *OTPService) SendCode(ctx context.Context, channel, dest, ip string) error {
	sender, ok := s.senders[channel]
	if !ok {
		return ErrUnknownChannel
	}

	can, err := s.otp.CanResend(ctx, dest)
	if err != nil {
		return fmt.Errorf("检查重发间隔失败: %w", err)
	}
	if !can {
		return ErrResendTooSoon
	}

	allowed, err := s.limiter.AllowSend(ctx, dest, ip)
	if err != nil {
		return fmt.Errorf("检查发送配额失败: %w", err)
	}
	if !allowed {
		return ErrSendRateLimited
	}

	code, err := s.otp.Issue(ctx, dest)
	if err != nil {
		return fmt.Errorf("生成验证码失败: %w", err)
	}
	if err := sender.SendCode(ctx, dest, code); err != nil {
		return fmt.Errorf("发送验证码失败: %w", err)
	}
	return nil
}
