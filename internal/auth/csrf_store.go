package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
)

// CSRFStore 为登录页表单签发一次性 CSRF token，绑定 linkedState（本会话一次性，防重放）。
type CSRFStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewCSRFStore 构造 CSRF token 存储。ttl 覆盖一次登录页停留期。
func NewCSRFStore(rdb *redis.Client, ttl time.Duration) *CSRFStore {
	return &CSRFStore{rdb: rdb, ttl: ttl}
}

func csrfKey(linkedState string) string { return "oauth:csrf:" + linkedState }

// Issue 为给定 linkedState 签发一次性 token 并返回。
func (s *CSRFStore) Issue(ctx context.Context, linkedState string) (string, error) {
	token := idgen.New("csrf")
	if err := s.rdb.Set(ctx, csrfKey(linkedState), token, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("签发 CSRF token 失败: %w", err)
	}
	return token, nil
}

// Validate 校验 token 与 linkedState 绑定一致但不消费（保留供后续提交再校验）。不匹配/不存在返回 false。
// 用于页面作用域的幂等子请求（如登出态忘记密码页的「发送验证码」），它可被多次点击且其后还要走表单提交，
// 故不能像 Consume 那样一次性删除——一次性消费留到最终提交。
func (s *CSRFStore) Validate(ctx context.Context, linkedState, token string) (bool, error) {
	stored, err := s.rdb.Get(ctx, csrfKey(linkedState)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取 CSRF token 失败: %w", err)
	}
	return stored == token && token != "", nil
}

// Consume 校验 token 与 linkedState 绑定的一致并删除（一次性）。不匹配/不存在返回 false。
func (s *CSRFStore) Consume(ctx context.Context, linkedState, token string) (bool, error) {
	stored, err := s.rdb.GetDel(ctx, csrfKey(linkedState)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("取用 CSRF token 失败: %w", err)
	}
	return stored == token && token != "", nil
}
