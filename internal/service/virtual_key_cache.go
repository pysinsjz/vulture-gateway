package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// VKeyCache 是 virtual key 热路径缓存契约（ADR-0014）：DB 为真相源，缓存失效回查。接口化以便单测假实现。
type VKeyCache interface {
	Get(ctx context.Context, userUUID string) (string, bool, error)
	Set(ctx context.Context, userUUID, key string) error
	Del(ctx context.Context, userUUID string) error
}

// redisVKeyCache 用 Redis 缓存 user→virtual key（带 TTL）。key 形如 vkey:{uuid}。
type redisVKeyCache struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewRedisVKeyCache 构造 Redis 缓存。ttl<=0 时回退默认 1h。
func NewRedisVKeyCache(rdb *redis.Client, ttl time.Duration) VKeyCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &redisVKeyCache{rdb: rdb, ttl: ttl}
}

func vkeyCacheKey(userUUID string) string { return "vkey:" + userUUID }

func (c *redisVKeyCache) Get(ctx context.Context, userUUID string) (string, bool, error) {
	val, err := c.rdb.Get(ctx, vkeyCacheKey(userUUID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("读取 virtual key 缓存失败: %w", err)
	}
	return val, true, nil
}

func (c *redisVKeyCache) Set(ctx context.Context, userUUID, key string) error {
	if err := c.rdb.Set(ctx, vkeyCacheKey(userUUID), key, c.ttl).Err(); err != nil {
		return fmt.Errorf("写入 virtual key 缓存失败: %w", err)
	}
	return nil
}

func (c *redisVKeyCache) Del(ctx context.Context, userUUID string) error {
	if err := c.rdb.Del(ctx, vkeyCacheKey(userUUID)).Err(); err != nil {
		return fmt.Errorf("清除 virtual key 缓存失败: %w", err)
	}
	return nil
}
