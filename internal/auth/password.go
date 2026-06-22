package auth

import "golang.org/x/crypto/bcrypt"

// defaultBcryptCost 是安全基线（ADR-0013）：cost 12。非法配置回落至此。
const defaultBcryptCost = 12

// PasswordHasher 抽象密码散列与校验，便于上层对内存假实现测试。
type PasswordHasher interface {
	// Hash 生成密码散列。明文超 bcrypt 72 字节上限时返回错误（不静默截断）。
	Hash(plain string) (string, error)
	// Compare 校验明文与散列是否匹配。散列非法或不匹配均返回 false，不 panic。
	Compare(hash, plain string) bool
}

type bcryptHasher struct {
	cost int
}

// NewBcryptHasher 构造 bcrypt 散列器。cost 越界（<MinCost 或 >MaxCost）时回落至安全基线 12。
func NewBcryptHasher(cost int) PasswordHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = defaultBcryptCost
	}
	return &bcryptHasher{cost: cost}
}

func (h *bcryptHasher) Hash(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), h.cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (h *bcryptHasher) Compare(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
