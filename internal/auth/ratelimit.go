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

func loginFailKey(identifier, ip string) string { return "rl:login:" + identifier + ":" + ip }
func sendQuotaKey(dest, ip string) string       { return "rl:send:" + dest + ":" + ip }

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

// RecordLoginFailure 记一次密码登录失败（identifier+IP），首次失败启动锁定窗口计时。
func (r *RateLimiter) RecordLoginFailure(ctx context.Context, identifier, ip string) error {
	_, err := r.incrWithWindow(ctx, loginFailKey(identifier, ip), r.cfg.LoginLockWindow)
	return err
}

// IsLoginLocked 报告该 identifier+IP 是否已达失败上限被锁定。
func (r *RateLimiter) IsLoginLocked(ctx context.Context, identifier, ip string) (bool, error) {
	n, err := r.rdb.Get(ctx, loginFailKey(identifier, ip)).Int()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取登录失败计数失败: %w", err)
	}
	return n >= r.cfg.LoginMaxFailures, nil
}

// ResetLogin 清零某 identifier+IP 的失败计数（登录成功时调用）。
func (r *RateLimiter) ResetLogin(ctx context.Context, identifier, ip string) error {
	if err := r.rdb.Del(ctx, loginFailKey(identifier, ip)).Err(); err != nil {
		return fmt.Errorf("清零登录失败计数失败: %w", err)
	}
	return nil
}

// AllowSend 在验证码发送配额内放行并计数；超过配额返回 false（按 dest+IP，固定窗口）。
func (r *RateLimiter) AllowSend(ctx context.Context, dest, ip string) (bool, error) {
	n, err := r.incrWithWindow(ctx, sendQuotaKey(dest, ip), r.cfg.SendWindow)
	if err != nil {
		return false, err
	}
	return int(n) <= r.cfg.SendMax, nil
}
