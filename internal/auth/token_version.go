package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// TokenVersionStore 维护每个 Device 当前有效的 token_version（ADR-0010 即时吊销）。
// 登出 / 设备吊销 / refresh 复用判盗只需 Bump，即可即时作废该 Device 所有在途 access JWT。
type TokenVersionStore struct {
	rdb *redis.Client
}

// NewTokenVersionStore 构造存储。
func NewTokenVersionStore(rdb *redis.Client) *TokenVersionStore {
	return &TokenVersionStore{rdb: rdb}
}

// key 与 docs/flows/auth.md 约定一致：device:{device_id}:token_version。
func key(deviceID string) string {
	return fmt.Sprintf("device:%s:token_version", deviceID)
}

// Current 返回该 Device 当前 token_version。exists 为 false 表示该 Device 无记录
// （未签发过 / 已被清理）——此时其任何 access JWT 都应被拒。
func (s *TokenVersionStore) Current(ctx context.Context, deviceID string) (version int64, exists bool, err error) {
	v, err := s.rdb.Get(ctx, key(deviceID)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("读取 token_version 失败: %w", err)
	}
	return v, true, nil
}

// Set 设置该 Device 的 token_version（脚手架签发时初始化为某个基线值）。
func (s *TokenVersionStore) Set(ctx context.Context, deviceID string, version int64) error {
	if err := s.rdb.Set(ctx, key(deviceID), version, 0).Err(); err != nil {
		return fmt.Errorf("写入 token_version 失败: %w", err)
	}
	return nil
}

// Bump 原子自增该 Device 的 token_version，返回自增后的新值。
// 这是即时吊销的触发动作：自增后，所有携带旧 token_version 的在途 access JWT 立即失效。
func (s *TokenVersionStore) Bump(ctx context.Context, deviceID string) (int64, error) {
	v, err := s.rdb.Incr(ctx, key(deviceID)).Result()
	if err != nil {
		return 0, fmt.Errorf("bump token_version 失败: %w", err)
	}
	return v, nil
}
