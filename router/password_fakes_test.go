package router_test

import (
	"context"
	"sync"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// memIdentityRepo 是 dao.IdentityRepository 的内存实现，供 router 级 HTTP 缝注入，
// 使「设密码 → 密码登录」端到端回路无需真实 PostgreSQL。以 *model.Identity 存储，
// UpdateSecret 原地改 secret，后续 FindByTypeIdentifier 能读到新值（账号级生效）。
type memIdentityRepo struct {
	mu    sync.Mutex
	items []*model.Identity
}

func newMemIdentityRepo() *memIdentityRepo { return &memIdentityRepo{} }

// seed 预置一条身份（测试构造账号初态用）。
func (r *memIdentityRepo) seed(id *model.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, id)
}

func (r *memIdentityRepo) FindByTypeIdentifier(_ context.Context, typ, identifier string) (*model.Identity, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.items {
		if id.Type == typ && id.Identifier == identifier {
			cp := *id
			return &cp, true, nil
		}
	}
	return nil, false, nil
}

func (r *memIdentityRepo) FindByUserUUIDAndType(_ context.Context, userUUID, typ string) (*model.Identity, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.items {
		if id.UserUUID == userUUID && id.Type == typ {
			cp := *id
			return &cp, true, nil
		}
	}
	return nil, false, nil
}

func (r *memIdentityRepo) ListLocalByUserUUID(_ context.Context, userUUID string) ([]model.Identity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.Identity
	for _, id := range r.items {
		if id.UserUUID == userUUID && id.Provider == "" {
			out = append(out, *id)
		}
	}
	return out, nil
}

func (r *memIdentityRepo) UpdateSecretByUserUUID(_ context.Context, userUUID, secretHash string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rows int64
	for _, id := range r.items {
		if id.UserUUID == userUUID && id.Provider == "" {
			id.Secret = secretHash
			rows++
		}
	}
	return rows, nil
}

func (r *memIdentityRepo) Create(_ context.Context, id *model.Identity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, id)
	return nil
}

// secretOf 取某 (type, identifier) 身份当前 secret（测试断言账号级写入用）。
func (r *memIdentityRepo) secretOf(typ, identifier string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.items {
		if id.Type == typ && id.Identifier == identifier {
			return id.Secret
		}
	}
	return ""
}

// memUserRepo 是 dao.UserRepository 的内存实现。本地用户的 subject 即 User.uuid（ADR-0013），
// 故密码登录解析出的 subject（= identity.UserUUID）经此幂等命中同一 User。
type memUserRepo struct{}

func (memUserRepo) ResolveOrCreateBySubject(_ context.Context, subject string) (*model.User, error) {
	return &model.User{UUID: subject, Subject: subject}, nil
}

func (memUserRepo) Create(_ context.Context, _ *model.User) error { return nil }

// passthroughTx 是透传事务器：直接执行回调，不开真实 DB 事务（内存仓无需事务语义）。
type passthroughTx struct{}

func (passthroughTx) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
