package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
)

// GWCode 是网关一次性授权码（GW_CODE）所绑定的数据。#12 的 /oauth/token 凭 code_verifier
// 校验 CodeChallenge、并据 UserUUID 创建 Device。
type GWCode struct {
	CodeChallenge string `json:"code_challenge"` // 绑定本次 PKCE challenge
	UserUUID      string `json:"user_uuid"`      // 登录成功解析出的 User
	RedirectURI   string `json:"redirect_uri"`   // 签发时的回调，token 请求需一致
}

// GWCodeStore 存储 GW_CODE（Redis）。TTL 60s、单次使用（Consume 用 GETDEL 保证原子取用）。
type GWCodeStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewGWCodeStore 构造存储。
func NewGWCodeStore(rdb *redis.Client, ttl time.Duration) *GWCodeStore {
	return &GWCodeStore{rdb: rdb, ttl: ttl}
}

func gwCodeKey(code string) string {
	return "oauth:gwcode:" + code
}

// Issue 生成并存储一枚 GW_CODE，返回码值。
func (s *GWCodeStore) Issue(ctx context.Context, data GWCode) (string, error) {
	code := idgen.New("gwc")
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("序列化 GW_CODE 失败: %w", err)
	}
	if err := s.rdb.Set(ctx, gwCodeKey(code), b, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("存储 GW_CODE 失败: %w", err)
	}
	return code, nil
}

// Consume 原子取回并删除 GW_CODE（单次使用）。found=false 表示不存在/已过期/已被用过。
func (s *GWCodeStore) Consume(ctx context.Context, code string) (data GWCode, found bool, err error) {
	raw, err := s.rdb.GetDel(ctx, gwCodeKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return GWCode{}, false, nil
	}
	if err != nil {
		return GWCode{}, false, fmt.Errorf("取用 GW_CODE 失败: %w", err)
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return GWCode{}, false, fmt.Errorf("反序列化 GW_CODE 失败: %w", err)
	}
	return data, true, nil
}
