package signin

import (
	"context"
	"fmt"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
)

// codeMethod 是「邮箱/手机 + 验证码」本地登录（Direct）。验证码通过即视为身份证明：
// 标识已有 Identity → 解析其 User；标识无 Identity → 登录即注册（事务建 User+Identity，secret 留空）。
// email_code 与 sms_code 共用此实现，仅 name 与 identityType 不同。
type codeMethod struct {
	directBase
	name         string
	identityType string
	otp          *auth.OTPStore
	identities   dao.IdentityRepository
	users        dao.UserRepository
	tx           dao.Transactor
}

// NewEmailCodeMethod 构造邮箱验证码登录方式。
func NewEmailCodeMethod(otp *auth.OTPStore, identities dao.IdentityRepository, users dao.UserRepository, tx dao.Transactor) SigninMethod {
	return &codeMethod{name: "email_code", identityType: model.IdentityTypeEmail, otp: otp, identities: identities, users: users, tx: tx}
}

// NewSmsCodeMethod 构造手机验证码登录方式。
func NewSmsCodeMethod(otp *auth.OTPStore, identities dao.IdentityRepository, users dao.UserRepository, tx dao.Transactor) SigninMethod {
	return &codeMethod{name: "sms_code", identityType: model.IdentityTypePhone, otp: otp, identities: identities, users: users, tx: tx}
}

func (m *codeMethod) Name() string { return m.name }

func (m *codeMethod) Verify(ctx context.Context, in VerifyInput) (string, error) {
	ok, err := m.otp.Verify(ctx, in.Identifier, in.Credential)
	if err != nil {
		return "", fmt.Errorf("校验验证码失败: %w", err)
	}
	if !ok {
		return "", ErrInvalidCode
	}

	identity, found, err := m.identities.FindByTypeIdentifier(ctx, m.identityType, in.Identifier)
	if err != nil {
		return "", fmt.Errorf("查询 Identity 失败: %w", err)
	}
	if found {
		return identity.UserUUID, nil
	}

	// 登录即注册：事务内同步建 User + Identity，secret 留空（仅验证码登录）。
	return m.register(ctx, in.Identifier)
}

func (m *codeMethod) register(ctx context.Context, identifier string) (string, error) {
	var userUUID string
	err := m.tx.WithinTx(ctx, func(ctx context.Context) error {
		user := &model.User{UUID: idgen.New("usr")}
		user.Subject = user.UUID // 本地用户的稳定身份锚＝自身 uuid
		if err := m.users.Create(ctx, user); err != nil {
			return err
		}
		identity := &model.Identity{
			UUID:       idgen.New("idn"),
			UserUUID:   user.UUID,
			Type:       m.identityType,
			Identifier: identifier,
		}
		if err := m.identities.Create(ctx, identity); err != nil {
			return err
		}
		userUUID = user.UUID
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("登录即注册失败: %w", err)
	}
	return userUUID, nil
}
