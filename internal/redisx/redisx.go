// Package redisx 封装 go-redis 客户端的构造。
package redisx

import (
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/config"
)

// NewClient 按配置构造 Redis 客户端。连通性在启动时由调用方 Ping 校验。
func NewClient(cfg config.RedisConfig) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}
