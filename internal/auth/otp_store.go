package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

// otpCodeMax 是 6 位数字验证码的上界（不含），生成区间 [0, 1000000)。
const otpCodeMax = 1000000

// OTPStore 管理验证码的下发、校验与防刷（ADR-0013 安全基线）。
// 码存 Redis：5min 有效期、单码最多试 N 次、按 dest 控制重发间隔。
type OTPStore struct {
	rdb            *redis.Client
	ttl            time.Duration
	resendInterval time.Duration
	maxAttempts    int
}

// NewOTPStore 构造验证码存储。ttl=有效期（5min）、resendInterval=重发间隔（60s）、maxAttempts=单码最大尝试（5）。
func NewOTPStore(rdb *redis.Client, ttl, resendInterval time.Duration, maxAttempts int) *OTPStore {
	return &OTPStore{rdb: rdb, ttl: ttl, resendInterval: resendInterval, maxAttempts: maxAttempts}
}

func otpCodeKey(dest string) string     { return "otp:code:" + dest }
func otpAttemptsKey(dest string) string { return "otp:attempts:" + dest }
func otpResendKey(dest string) string   { return "otp:resend:" + dest }

// generateCode 用 crypto/rand 生成无模偏的 6 位数字验证码。
func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(otpCodeMax))
	if err != nil {
		return "", fmt.Errorf("生成验证码失败: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// Issue 生成并下发验证码：写入码与尝试计数（TTL=ttl），并置重发闸（TTL=resendInterval）。返回明文码供发送。
func (s *OTPStore) Issue(ctx context.Context, dest string) (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, otpCodeKey(dest), code, s.ttl)
	pipe.Set(ctx, otpAttemptsKey(dest), 0, s.ttl)
	pipe.Set(ctx, otpResendKey(dest), 1, s.resendInterval)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("下发验证码失败: %w", err)
	}
	return code, nil
}

// CanResend 报告 dest 是否已过重发间隔（重发闸不存在即可重发）。
func (s *OTPStore) CanResend(ctx context.Context, dest string) (bool, error) {
	n, err := s.rdb.Exists(ctx, otpResendKey(dest)).Result()
	if err != nil {
		return false, fmt.Errorf("查询重发闸失败: %w", err)
	}
	return n == 0, nil
}

// Verify 校验 dest 的验证码：码不存在/已过期→false；尝试已达上限→false（单码作废）；
// 命中→删除全部相关键并返回 true；未命中→尝试计数 +1，达上限则作废该码。
func (s *OTPStore) Verify(ctx context.Context, dest, code string) (bool, error) {
	stored, err := s.rdb.Get(ctx, otpCodeKey(dest)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取验证码失败: %w", err)
	}

	attempts, err := s.rdb.Get(ctx, otpAttemptsKey(dest)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, fmt.Errorf("读取尝试计数失败: %w", err)
	}
	if attempts >= s.maxAttempts {
		return false, nil
	}

	if stored == code {
		s.rdb.Del(ctx, otpCodeKey(dest), otpAttemptsKey(dest))
		return true, nil
	}

	n, err := s.rdb.Incr(ctx, otpAttemptsKey(dest)).Result()
	if err != nil {
		return false, fmt.Errorf("累加尝试计数失败: %w", err)
	}
	if int(n) >= s.maxAttempts {
		// 达上限：作废该码，后续即便正确也不再通过。
		s.rdb.Del(ctx, otpCodeKey(dest))
	}
	return false, nil
}
