package signin

import (
	"context"
	"fmt"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
)

// passwordMethod 是「邮箱/手机 + 密码」本地登录（Direct）。
// 凭据为 RSA 密文密码：解密 → 按标识查 Identity → bcrypt 校验 secret；失败按 identifier+IP 限流。
// 密码登录要求账号已存在且已设密码（secret 非空），不做登录即注册。
type passwordMethod struct {
	directBase
	identities dao.IdentityRepository
	hasher     auth.PasswordHasher
	rsa        *auth.RSADecryptor
	limiter    *auth.RateLimiter
}

// NewPasswordMethod 构造密码登录方式。
func NewPasswordMethod(identities dao.IdentityRepository, hasher auth.PasswordHasher, rsa *auth.RSADecryptor, limiter *auth.RateLimiter) SigninMethod {
	return &passwordMethod{identities: identities, hasher: hasher, rsa: rsa, limiter: limiter}
}

func (m *passwordMethod) Name() string { return "password" }

func (m *passwordMethod) Verify(ctx context.Context, in VerifyInput) (string, error) {
	// 先查锁定：失败过多则直接拒，避免无谓的解密/查库/bcrypt 开销。
	locked, err := m.limiter.IsLoginLocked(ctx, in.Identifier, in.IP)
	if err != nil {
		return "", fmt.Errorf("查询登录锁定状态失败: %w", err)
	}
	if locked {
		return "", ErrAccountLocked
	}

	plain, err := m.rsa.Decrypt(in.Credential)
	if err != nil {
		// 密文异常视为一次失败尝试（防爆破/探测）。
		return "", m.fail(ctx, in)
	}

	typ := classifyIdentifier(in.Identifier)
	identity, found, err := m.identities.FindByTypeIdentifier(ctx, typ, in.Identifier)
	if err != nil {
		return "", fmt.Errorf("查询 Identity 失败: %w", err)
	}
	// 账号不存在或未设密码（仅验证码登录）→ 统一报凭据错，防账号枚举。
	if !found || identity.Secret == "" {
		return "", m.fail(ctx, in)
	}

	if !m.hasher.Compare(identity.Secret, plain) {
		return "", m.fail(ctx, in)
	}

	// 成功：清零失败计数，返回 User.uuid 作 subject。
	if err := m.limiter.ResetLogin(ctx, in.Identifier, in.IP); err != nil {
		return "", fmt.Errorf("清零登录失败计数失败: %w", err)
	}
	return identity.UserUUID, nil
}

// fail 记一次登录失败，返回统一凭据错误；若本次失败触发锁定则返回锁定错误。
func (m *passwordMethod) fail(ctx context.Context, in VerifyInput) error {
	if err := m.limiter.RecordLoginFailure(ctx, in.Identifier, in.IP); err != nil {
		return fmt.Errorf("记录登录失败失败: %w", err)
	}
	if locked, err := m.limiter.IsLoginLocked(ctx, in.Identifier, in.IP); err == nil && locked {
		return ErrAccountLocked
	}
	return ErrInvalidCredentials
}
