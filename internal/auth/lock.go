package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Locker 是基于 Redis 的轻量互斥锁，用于串行化同一 refresh token 的并发刷新，避免误判。
type Locker struct {
	rdb *redis.Client
}

// NewLocker 构造锁。
func NewLocker(rdb *redis.Client) *Locker {
	return &Locker{rdb: rdb}
}

// Acquire 尝试获取锁（SET NX EX）。acquired=false 表示已被他人持有。
func (l *Locker) Acquire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	ok, err := l.rdb.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("获取锁失败: %w", err)
	}
	return ok, nil
}

// Release 释放锁。TTL 为兜底，正常路径主动删除。
func (l *Locker) Release(ctx context.Context, key string) {
	_ = l.rdb.Del(ctx, key).Err()
}
