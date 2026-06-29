package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimitConfig 限流参数（ADR-0013 安全基线）。
type RateLimitConfig struct {
	LoginMaxFailures int           // 密码登录失败上限（默认 5）
	LoginLockWindow  time.Duration // 锁定时长（默认 15min）
	SendMax          int           // 验证码发送配额（每窗口，按 dest+IP）
	SendWindow       time.Duration // 验证码发送配额窗口
}

// RateLimiter 提供两类防滥用计数（Redis 固定窗口）：
//   - 密码登录失败按 identifier+IP 计数，达上限锁定一段时间（防爆破）；
//   - 验证码发送按 dest+IP 限配额（防短信/邮件轰炸）。
type RateLimiter struct {
	rdb *redis.Client
	cfg RateLimitConfig
}

// NewRateLimiter 构造限流器。
func NewRateLimiter(rdb *redis.Client, cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{rdb: rdb, cfg: cfg}
}

// FailureScope 隔离不同凭据操作的失败计数命名空间（与 OTP Purpose 同构，ADR-0015）：
// 登录失败与改密失败各自独立，互不污染、互不解锁。
type FailureScope string

const (
	// ScopeLogin 密码登录失败（默认作用域，向后兼容：key 与历史 rl:login:* 字节一致）。
	ScopeLogin FailureScope = "login"
	// ScopePasswordReset 改密验证码失败（独立锁，避免与登录锁交叉污染）。
	ScopePasswordReset FailureScope = "pwreset"
)

func failKey(scope FailureScope, identifier, ip string) string {
	return "rl:" + string(scope) + ":" + identifier + ":" + ip
}
func sendQuotaKey(dest, ip string) string { return "rl:send:" + dest + ":" + ip }

// incrWithWindow 对 key 自增并在首次自增时设置窗口 TTL（固定窗口计数）。
func (r *RateLimiter) incrWithWindow(ctx context.Context, key string, window time.Duration) (int64, error) {
	n, err := r.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("计数自增失败: %w", err)
	}
	if n == 1 {
		if err := r.rdb.Expire(ctx, key, window).Err(); err != nil {
			return 0, fmt.Errorf("设置窗口 TTL 失败: %w", err)
		}
	}
	return n, nil
}

// RecordFailure 记一次某作用域的凭据失败（identifier+IP），首次失败启动锁定窗口计时。
func (r *RateLimiter) RecordFailure(ctx context.Context, scope FailureScope, identifier, ip string) error {
	_, err := r.incrWithWindow(ctx, failKey(scope, identifier, ip), r.cfg.LoginLockWindow)
	return err
}

// IsLocked 报告该作用域下 identifier+IP 是否已达失败上限被锁定。
func (r *RateLimiter) IsLocked(ctx context.Context, scope FailureScope, identifier, ip string) (bool, error) {
	n, err := r.rdb.Get(ctx, failKey(scope, identifier, ip)).Int()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取失败计数失败: %w", err)
	}
	return n >= r.cfg.LoginMaxFailures, nil
}

// ResetFailures 清零某作用域下 identifier+IP 的失败计数（该作用域操作成功时调用）。
func (r *RateLimiter) ResetFailures(ctx context.Context, scope FailureScope, identifier, ip string) error {
	if err := r.rdb.Del(ctx, failKey(scope, identifier, ip)).Err(); err != nil {
		return fmt.Errorf("清零失败计数失败: %w", err)
	}
	return nil
}

// RecordLoginFailure 记一次密码登录失败（作用域 login），向后兼容封装。
func (r *RateLimiter) RecordLoginFailure(ctx context.Context, identifier, ip string) error {
	return r.RecordFailure(ctx, ScopeLogin, identifier, ip)
}

// IsLoginLocked 报告该 identifier+IP 是否已达登录失败上限被锁定（作用域 login）。
func (r *RateLimiter) IsLoginLocked(ctx context.Context, identifier, ip string) (bool, error) {
	return r.IsLocked(ctx, ScopeLogin, identifier, ip)
}

// ResetLogin 清零某 identifier+IP 的登录失败计数（登录成功时调用，作用域 login）。
func (r *RateLimiter) ResetLogin(ctx context.Context, identifier, ip string) error {
	return r.ResetFailures(ctx, ScopeLogin, identifier, ip)
}

// AllowSend 在验证码发送配额内放行并计数；超过配额返回 false（按 dest+IP，固定窗口）。
func (r *RateLimiter) AllowSend(ctx context.Context, dest, ip string) (bool, error) {
	n, err := r.incrWithWindow(ctx, sendQuotaKey(dest, ip), r.cfg.SendWindow)
	if err != nil {
		return false, err
	}
	return int(n) <= r.cfg.SendMax, nil
}
