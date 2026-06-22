package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// AuthzRequest 是 /oauth/authorize 通过校验后服务端暂存的内容，按关联 state（linkedState）索引。
// 上游回调时凭 linkedState 取回，用于换码、回跳与 PKCE 透传。
type AuthzRequest struct {
	OrigState     string `json:"orig_state"`     // 桌面端原始 state，回跳时原样带回
	CodeChallenge string `json:"code_challenge"` // PKCE challenge（S256），透传至 GW_CODE
	RedirectURI   string `json:"redirect_uri"`   // 桌面端回环回调
	Nonce         string `json:"nonce"`          // 上游 OIDC nonce，回调时校验 id_token 防注入/重放（ADR-0012）
}

// AuthzStore 暂存 authorize 请求（Redis），TTL 覆盖一次授权流程的存活期。
type AuthzStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewAuthzStore 构造暂存。
func NewAuthzStore(rdb *redis.Client, ttl time.Duration) *AuthzStore {
	return &AuthzStore{rdb: rdb, ttl: ttl}
}

func authzKey(linkedState string) string {
	return "oauth:authz:" + linkedState
}

// Save 暂存一条 authorize 请求。
func (s *AuthzStore) Save(ctx context.Context, linkedState string, req AuthzRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化 authz 请求失败: %w", err)
	}
	if err := s.rdb.Set(ctx, authzKey(linkedState), b, s.ttl).Err(); err != nil {
		return fmt.Errorf("暂存 authz 请求失败: %w", err)
	}
	return nil
}

// Peek 读取但不删除，供渲染登录页时校验 linkedState 有效（GET 不应消费，否则刷新即失效）。
// 真正消费在登录提交成功时由 Take 完成。found=false 表示不存在或已过期。
func (s *AuthzStore) Peek(ctx context.Context, linkedState string) (req AuthzRequest, found bool, err error) {
	raw, err := s.rdb.Get(ctx, authzKey(linkedState)).Bytes()
	if errors.Is(err, redis.Nil) {
		return AuthzRequest{}, false, nil
	}
	if err != nil {
		return AuthzRequest{}, false, fmt.Errorf("读取 authz 请求失败: %w", err)
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return AuthzRequest{}, false, fmt.Errorf("反序列化 authz 请求失败: %w", err)
	}
	return req, true, nil
}

// Take 取回并删除（一次性）。found=false 表示不存在或已过期/已被取用。
func (s *AuthzStore) Take(ctx context.Context, linkedState string) (req AuthzRequest, found bool, err error) {
	raw, err := s.rdb.GetDel(ctx, authzKey(linkedState)).Bytes()
	if errors.Is(err, redis.Nil) {
		return AuthzRequest{}, false, nil
	}
	if err != nil {
		return AuthzRequest{}, false, fmt.Errorf("取回 authz 请求失败: %w", err)
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return AuthzRequest{}, false, fmt.Errorf("反序列化 authz 请求失败: %w", err)
	}
	return req, true, nil
}
