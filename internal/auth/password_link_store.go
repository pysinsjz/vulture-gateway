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

// PasswordLink 是「登录态首次设密码」绑定路径的一次性凭据（ADR-0015）。桌面端持 Bearer 经
// POST /api/v1/auth/password-link 铸取，把「已认证的 User」携带进系统浏览器里的托管密码页——
// 托管页本身没有桌面 Bearer，故靠这枚页面作用域的 token 证明「是谁」。
type PasswordLink struct {
	UserUUID string `json:"user_uuid"` // 铸取链接时持 Bearer 的 User
}

// PasswordLinkStore 存储 Password Link（Redis）。与 GWCodeStore 同构：TTL 5 分钟、单次使用
// （Take 用 GETDEL 原子取删，防重放）。Peek 在页面渲染时只读校验，成功写入密码后才 Take 消费。
type PasswordLinkStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewPasswordLinkStore 构造存储。ttl 为链接寿命（ADR-0015：5 分钟）。
func NewPasswordLinkStore(rdb *redis.Client, ttl time.Duration) *PasswordLinkStore {
	return &PasswordLinkStore{rdb: rdb, ttl: ttl}
}

func pwLinkKey(token string) string { return "pwlink:" + token }

// Issue 生成并存储一枚 Password Link，返回 token 值。
func (s *PasswordLinkStore) Issue(ctx context.Context, data PasswordLink) (string, error) {
	token := idgen.New("pwl")
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("序列化 Password Link 失败: %w", err)
	}
	if err := s.rdb.Set(ctx, pwLinkKey(token), b, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("存储 Password Link 失败: %w", err)
	}
	return token, nil
}

// Peek 只读取回 Password Link，不消费（供页面渲染校验，不影响后续提交）。
// found=false 表示不存在/已过期/已被消费。
func (s *PasswordLinkStore) Peek(ctx context.Context, token string) (data PasswordLink, found bool, err error) {
	raw, err := s.rdb.Get(ctx, pwLinkKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return PasswordLink{}, false, nil
	}
	if err != nil {
		return PasswordLink{}, false, fmt.Errorf("读取 Password Link 失败: %w", err)
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return PasswordLink{}, false, fmt.Errorf("反序列化 Password Link 失败: %w", err)
	}
	return data, true, nil
}

// Take 原子取回并删除 Password Link（单次使用，设密码成功后调用）。
// found=false 表示不存在/已过期/已被用过。
func (s *PasswordLinkStore) Take(ctx context.Context, token string) (data PasswordLink, found bool, err error) {
	raw, err := s.rdb.GetDel(ctx, pwLinkKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return PasswordLink{}, false, nil
	}
	if err != nil {
		return PasswordLink{}, false, fmt.Errorf("取用 Password Link 失败: %w", err)
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return PasswordLink{}, false, fmt.Errorf("反序列化 Password Link 失败: %w", err)
	}
	return data, true, nil
}
