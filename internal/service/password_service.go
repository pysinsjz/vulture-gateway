package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// 设密码业务错误（哨兵值），供 handler 映射为用户可见提示。
var (
	// ErrNoLocalIdentity 该 User 无本地身份（仅第三方 oauth）——无可承载密码的标识，无法设密码（ADR-0015）。
	ErrNoLocalIdentity = errors.New("无可设置密码的本地标识")
	// ErrPasswordAlreadySet 该 User 已设密码（secret 非空）。本切片（#39）只做首设；改密走验证码路径（#40）。
	ErrPasswordAlreadySet = errors.New("账号已设置密码")
	// ErrInvalidCiphertext 密文无法解密（base64 损坏 / 非配对公钥加密）。
	ErrInvalidCiphertext = errors.New("密码密文无效")
)

// PasswordBinding 是绑定模式页（GET /oauth/password?t=）所需的账号上下文：
// 预填标识 + 是否可首设（无密码且有本地标识）。
type PasswordBinding struct {
	Identifier string // 预填用的本地标识（优先 email）
	CanSet     bool   // 是否处于「可首设」状态：有本地标识且尚未设密码
}

// PasswordService 编排「登录态首次设密码」（ADR-0015 绑定路径，免 OTP）：
// 解密前端 RSA 密文 → 校验密码策略 → 在事务内把 bcrypt hash 写入该 User 名下所有本地身份。
// 改密（secret 非空）不在本切片范围，遇到则拒（ErrPasswordAlreadySet），留给 #40。
type PasswordService struct {
	identities dao.IdentityRepository
	hasher     auth.PasswordHasher
	rsa        *auth.RSADecryptor
	tx         dao.Transactor
}

// NewPasswordService 构造设密码服务。
func NewPasswordService(identities dao.IdentityRepository, hasher auth.PasswordHasher, rsa *auth.RSADecryptor, tx dao.Transactor) *PasswordService {
	return &PasswordService{identities: identities, hasher: hasher, rsa: rsa, tx: tx}
}

// Binding 查该 User 的绑定上下文：预填标识与是否可首设。
// 无本地身份返回 ErrNoLocalIdentity；已设密码则 CanSet=false（首设入口对其不可用）。
func (s *PasswordService) Binding(ctx context.Context, userUUID string) (PasswordBinding, error) {
	locals, err := s.identities.ListLocalByUserUUID(ctx, userUUID)
	if err != nil {
		return PasswordBinding{}, fmt.Errorf("查询本地身份失败: %w", err)
	}
	if len(locals) == 0 {
		return PasswordBinding{}, ErrNoLocalIdentity
	}
	return PasswordBinding{
		Identifier: preferredIdentifier(locals),
		CanSet:     !hasAnySecret(locals),
	}, nil
}

// SetInitialPassword 执行「首次设密码」：解密 → 校验策略 → 账号级写入。
// 仅当该 User 有本地标识且 secret 全空时写入；否则返回对应哨兵错误，调用方不应改动任何 secret。
// 密码策略错误（auth.ErrPassword*）直接透传，供 handler 精确提示。
func (s *PasswordService) SetInitialPassword(ctx context.Context, userUUID, encryptedB64 string) error {
	locals, err := s.identities.ListLocalByUserUUID(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("查询本地身份失败: %w", err)
	}
	if len(locals) == 0 {
		return ErrNoLocalIdentity
	}
	if hasAnySecret(locals) {
		return ErrPasswordAlreadySet
	}

	plain, err := s.rsa.Decrypt(encryptedB64)
	if err != nil {
		return ErrInvalidCiphertext
	}
	if err := auth.ValidatePassword(plain); err != nil {
		return err // 透传 auth.ErrPassword* 哨兵
	}

	hash, err := s.hasher.Hash(plain)
	if err != nil {
		return fmt.Errorf("散列密码失败: %w", err)
	}

	// 账号级写入：多行更新在事务内完成（写到该 User 所有本地身份）。
	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		rows, err := s.identities.UpdateSecretByUserUUID(ctx, userUUID, hash)
		if err != nil {
			return fmt.Errorf("写入密码失败: %w", err)
		}
		if rows == 0 {
			// 与前置 ListLocal 之间出现并发删除等异常：不静默成功。
			return ErrNoLocalIdentity
		}
		return nil
	})
}

// preferredIdentifier 选预填标识：优先 email，否则首个本地标识。
func preferredIdentifier(locals []model.Identity) string {
	for _, id := range locals {
		if id.Type == model.IdentityTypeEmail {
			return id.Identifier
		}
	}
	if len(locals) > 0 {
		return locals[0].Identifier
	}
	return ""
}

// hasAnySecret 该组身份是否已有任一非空 secret（即已设密码）。
func hasAnySecret(locals []model.Identity) bool {
	for _, id := range locals {
		if id.Secret != "" {
			return true
		}
	}
	return false
}
