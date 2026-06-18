package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RefreshPair 是一次刷新签发的令牌对，用于 60s 幂等宽限窗内的重放。
type RefreshPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshReplayStore 按「被轮换的旧 RT 哈希」缓存其签发的令牌对，TTL=宽限窗（60s）。
// 旧 RT 在窗内重放即返回同一对（容忍弱网/重试）；窗外缓存消失即触发判盗。
// 明文仅在此短存（60s），持久层始终只存哈希。
type RefreshReplayStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewRefreshReplayStore 构造存储，ttl 即宽限窗。
func NewRefreshReplayStore(rdb *redis.Client, ttl time.Duration) *RefreshReplayStore {
	return &RefreshReplayStore{rdb: rdb, ttl: ttl}
}

func replayKey(oldHash string) string {
	return "oauth:refresh:replay:" + oldHash
}

// Save 缓存旧 RT 哈希对应的令牌对。
func (s *RefreshReplayStore) Save(ctx context.Context, oldHash string, pair RefreshPair) error {
	b, err := json.Marshal(pair)
	if err != nil {
		return fmt.Errorf("序列化重放对失败: %w", err)
	}
	if err := s.rdb.Set(ctx, replayKey(oldHash), b, s.ttl).Err(); err != nil {
		return fmt.Errorf("缓存重放对失败: %w", err)
	}
	return nil
}

// Get 读取旧 RT 哈希对应的令牌对。found=false 表示宽限窗已过或从未轮换。
func (s *RefreshReplayStore) Get(ctx context.Context, oldHash string) (pair RefreshPair, found bool, err error) {
	raw, err := s.rdb.Get(ctx, replayKey(oldHash)).Bytes()
	if errors.Is(err, redis.Nil) {
		return RefreshPair{}, false, nil
	}
	if err != nil {
		return RefreshPair{}, false, fmt.Errorf("读取重放对失败: %w", err)
	}
	if err := json.Unmarshal(raw, &pair); err != nil {
		return RefreshPair{}, false, fmt.Errorf("反序列化重放对失败: %w", err)
	}
	return pair, true, nil
}
