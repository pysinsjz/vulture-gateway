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

// Purpose 是验证码的用途，用于 Redis key 命名空间隔离（ADR-0015）：登录与改密各自独立，
// 一个用途签发的码不能用于另一用途校验，重发冷却与试错计数也各用途独立。
type Purpose string

const (
	// PurposeLogin 登录验证码（默认用途，向后兼容）。
	PurposeLogin Purpose = "login"
	// PurposePasswordReset 改密验证码（secret 非空时二次确认）。
	PurposePasswordReset Purpose = "pwreset"
)

// resolvePurpose 取可选用途参数的首项；缺省/空串回落到 PurposeLogin（登录侧行为不变、向后兼容）。
func resolvePurpose(purpose []Purpose) Purpose {
	if len(purpose) > 0 && purpose[0] != "" {
		return purpose[0]
	}
	return PurposeLogin
}

// OTPStore 管理验证码的下发、校验与防刷（ADR-0013 安全基线）。
// 码存 Redis：5min 有效期、单码最多试 N 次、按 dest 控制重发间隔。
type OTPStore struct {
	rdb            *redis.Client
	ttl            time.Duration
	resendInterval time.Duration
	maxAttempts    int
	// bypassCode 是 dev/test 专用的「万能验证码」：非空时，提交该码即直接通过校验，
	// 免去查真实码的麻烦（便于手动在登录页验证）。务必仅在 dev/test 注入；
	// prod/staging 必须为空（由 config.validate 硬阻止 + wire 装配按 env 过滤双重保险）。
	bypassCode string
}

// NewOTPStore 构造验证码存储。ttl=有效期（5min）、resendInterval=重发间隔（60s）、maxAttempts=单码最大尝试（5）。
// bypassCode 为 dev/test 万能码（空=禁用，生产必须空）。
func NewOTPStore(rdb *redis.Client, ttl, resendInterval time.Duration, maxAttempts int, bypassCode string) *OTPStore {
	return &OTPStore{rdb: rdb, ttl: ttl, resendInterval: resendInterval, maxAttempts: maxAttempts, bypassCode: bypassCode}
}

// key 命名空间含 purpose：otp:<purpose>:<kind>:<dest>，使登录与改密的码/计数/重发闸彼此隔离。
func otpCodeKey(purpose Purpose, dest string) string {
	return "otp:" + string(purpose) + ":code:" + dest
}
func otpAttemptsKey(purpose Purpose, dest string) string {
	return "otp:" + string(purpose) + ":attempts:" + dest
}
func otpResendKey(purpose Purpose, dest string) string {
	return "otp:" + string(purpose) + ":resend:" + dest
}

// generateCode 用 crypto/rand 生成无模偏的 6 位数字验证码。
func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(otpCodeMax))
	if err != nil {
		return "", fmt.Errorf("生成验证码失败: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// Issue 生成并下发某用途的验证码：写入码与尝试计数（TTL=ttl），并置重发闸（TTL=resendInterval）。
// purpose 缺省为 login（向后兼容）。返回明文码供发送。
func (s *OTPStore) Issue(ctx context.Context, dest string, purpose ...Purpose) (string, error) {
	p := resolvePurpose(purpose)
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, otpCodeKey(p, dest), code, s.ttl)
	pipe.Set(ctx, otpAttemptsKey(p, dest), 0, s.ttl)
	pipe.Set(ctx, otpResendKey(p, dest), 1, s.resendInterval)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("下发验证码失败: %w", err)
	}
	return code, nil
}

// CanResend 报告 dest 在某用途下是否已过重发间隔（重发闸不存在即可重发）。purpose 缺省为 login。
func (s *OTPStore) CanResend(ctx context.Context, dest string, purpose ...Purpose) (bool, error) {
	p := resolvePurpose(purpose)
	n, err := s.rdb.Exists(ctx, otpResendKey(p, dest)).Result()
	if err != nil {
		return false, fmt.Errorf("查询重发闸失败: %w", err)
	}
	return n == 0, nil
}

// Verify 校验 dest 在某用途下的验证码：码不存在/已过期→false；尝试已达上限→false（单码作废）；
// 命中→删除全部相关键并返回 true；未命中→尝试计数 +1，达上限则作废该码。purpose 缺省为 login。
// 用途隔离：另一用途签发的码因命名空间不同而查不到，自然不通过。
func (s *OTPStore) Verify(ctx context.Context, dest, code string, purpose ...Purpose) (bool, error) {
	p := resolvePurpose(purpose)
	// dev/test 万能码：直接放行并清理可能残留的真实码/计数（生产 bypassCode 恒为空，不触发）。
	if s.bypassCode != "" && code == s.bypassCode {
		s.rdb.Del(ctx, otpCodeKey(p, dest), otpAttemptsKey(p, dest))
		return true, nil
	}

	stored, err := s.rdb.Get(ctx, otpCodeKey(p, dest)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取验证码失败: %w", err)
	}

	attempts, err := s.rdb.Get(ctx, otpAttemptsKey(p, dest)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, fmt.Errorf("读取尝试计数失败: %w", err)
	}
	if attempts >= s.maxAttempts {
		return false, nil
	}

	if stored == code {
		s.rdb.Del(ctx, otpCodeKey(p, dest), otpAttemptsKey(p, dest))
		return true, nil
	}

	n, err := s.rdb.Incr(ctx, otpAttemptsKey(p, dest)).Result()
	if err != nil {
		return false, fmt.Errorf("累加尝试计数失败: %w", err)
	}
	if int(n) >= s.maxAttempts {
		// 达上限：作废该码，后续即便正确也不再通过。
		s.rdb.Del(ctx, otpCodeKey(p, dest))
	}
	return false, nil
}
