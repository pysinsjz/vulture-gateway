package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// 设密码业务错误（哨兵值），供 handler 映射为用户可见提示。
var (
	// ErrNoLocalIdentity 该 User 无本地身份（仅第三方 oauth）——无可承载密码的标识，无法设密码（ADR-0015）。
	ErrNoLocalIdentity = errors.New("无可设置密码的本地标识")
	// ErrPasswordAlreadySet 该 User 已设密码（secret 非空）。首设入口（SetInitialPassword）对其不可用；改密走 ResetPassword。
	ErrPasswordAlreadySet = errors.New("账号已设置密码")
	// ErrInvalidCiphertext 密文无法解密（base64 损坏 / 非配对公钥加密）。
	ErrInvalidCiphertext = errors.New("密码密文无效")
	// ErrResetCodeRequired 改密（secret 非空）必须提供验证码二次确认，但请求缺码。
	ErrResetCodeRequired = errors.New("改密需验证码")
	// ErrResetCodeInvalid 改密验证码错误或已失效（含用途隔离：login 码用于 pwreset 自然不通过）。
	ErrResetCodeInvalid = errors.New("验证码错误或已失效")
	// ErrResetLocked 改密失败按 identifier+IP 触顶被锁定（复用 RateLimiter，防爆破）。
	ErrResetLocked = errors.New("尝试过于频繁，请稍后再试")
)

// PasswordBinding 是绑定模式页（GET /oauth/password?t=）所需的账号上下文：
// 预填标识 + 是否可首设（无密码且有本地标识）。
type PasswordBinding struct {
	Identifier string // 预填用的本地标识（优先 email）
	CanSet     bool   // 是否处于「可首设」状态：有本地标识且尚未设密码
}

// PasswordService 编排「设置 / 重置密码」（ADR-0015）：
//   - 首设（secret 空，绑定路径免 OTP）：解密 → 策略 → 账号级写入（SetInitialPassword）。
//   - 改密（secret 非空，需 pwreset 验证码二次确认）：锁定检查 → 策略 → 验码 → 账号级写入（ResetPassword）。
//
// 账号级写入：把 bcrypt hash 写入该 User 名下所有本地身份（事务内）。
type PasswordService struct {
	identities dao.IdentityRepository
	hasher     auth.PasswordHasher
	rsa        *auth.RSADecryptor
	tx         dao.Transactor
	otp        *auth.OTPStore
	limiter    *auth.RateLimiter
}

// NewPasswordService 构造设密码服务。otp/limiter 供改密路径做 pwreset 验码与失败限流（首设路径不用）。
func NewPasswordService(identities dao.IdentityRepository, hasher auth.PasswordHasher, rsa *auth.RSADecryptor, tx dao.Transactor, otp *auth.OTPStore, limiter *auth.RateLimiter) *PasswordService {
	return &PasswordService{identities: identities, hasher: hasher, rsa: rsa, tx: tx, otp: otp, limiter: limiter}
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
	return s.writeAccountSecret(ctx, userUUID, hash)
}

// ResetChannel 解析改密验证码的目标标识与渠道（优先 email），供发码端点定位「发给谁、走哪条渠道」。
// 与 ResetPassword 的验码目标同源（均取 preferredLocal），确保「发到哪、验哪」一致。
// 无本地标识返回 ErrNoLocalIdentity。
func (s *PasswordService) ResetChannel(ctx context.Context, userUUID string) (dest, channel string, err error) {
	locals, err := s.identities.ListLocalByUserUUID(ctx, userUUID)
	if err != nil {
		return "", "", fmt.Errorf("查询本地身份失败: %w", err)
	}
	if len(locals) == 0 {
		return "", "", ErrNoLocalIdentity
	}
	id := preferredLocal(locals)
	switch id.Type {
	case model.IdentityTypeEmail:
		return id.Identifier, model.ProviderCategoryEmail, nil
	case model.IdentityTypePhone:
		return id.Identifier, model.ProviderCategorySMS, nil
	default:
		return "", "", ErrNoLocalIdentity
	}
}

// ResetPassword 执行「改密」（secret 非空，需 pwreset 验证码）：锁定检查 → 解密 + 策略校验 →
// 验证 pwreset 验证码（命中即消费）→ 账号级写入。失败（锁定/缺码/错码/策略）一律不改动任何 secret。
// 改密失败按 identifier(=验码目标)+IP 计入现有 RateLimiter，触顶锁定；成功清零。
func (s *PasswordService) ResetPassword(ctx context.Context, userUUID, encryptedB64, code, ip string) error {
	locals, err := s.identities.ListLocalByUserUUID(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("查询本地身份失败: %w", err)
	}
	if len(locals) == 0 {
		return ErrNoLocalIdentity
	}
	dest := preferredLocal(locals).Identifier

	// 先查锁定（作用域 pwreset，与登录锁独立）：触顶则直接拒，避免无谓的解密/验码开销。
	locked, err := s.limiter.IsLocked(ctx, auth.ScopePasswordReset, dest, ip)
	if err != nil {
		return fmt.Errorf("查询改密锁定状态失败: %w", err)
	}
	if locked {
		return ErrResetLocked
	}

	// 缺码不计失败（纯用户漏填，非爆破）：直接提示需验证码。
	if code == "" {
		return ErrResetCodeRequired
	}

	// 先做解密与策略校验（不消费验证码）：这些是用户输入纠错，不应消费 OTP、也不算爆破失败。
	plain, err := s.rsa.Decrypt(encryptedB64)
	if err != nil {
		return ErrInvalidCiphertext
	}
	if err := auth.ValidatePassword(plain); err != nil {
		return err // 透传 auth.ErrPassword* 哨兵
	}

	// 验证 pwreset 验证码（用途隔离：login 码因命名空间不同自然不通过）；命中即消费（单码一次性）。
	ok, err := s.otp.Verify(ctx, dest, code, auth.PurposePasswordReset)
	if err != nil {
		return fmt.Errorf("校验改密验证码失败: %w", err)
	}
	if !ok {
		return s.recordResetFailure(ctx, dest, ip)
	}

	hash, err := s.hasher.Hash(plain)
	if err != nil {
		return fmt.Errorf("散列密码失败: %w", err)
	}
	if err := s.writeAccountSecret(ctx, userUUID, hash); err != nil {
		return err
	}

	// 成功：清零改密失败计数（best-effort——secret 已落库，清零是收尾，失败不应反报成功为错误）。
	_ = s.limiter.ResetFailures(ctx, auth.ScopePasswordReset, dest, ip)
	return nil
}

// ForgotPassword 执行登出态「忘记密码」设/重置（ADR-0015 / #41）：用 identifier + pwreset 验证码
// 证明身份后写账号级密码。登出态一律需验证码（无 Bearer、无 Password Link），set/reset 由该 User 的
// secret 空/非空派生——仅影响调用方的成功语义，验证码闸两者皆同。
//
// 防账号枚举：码校验先行且与「标识不存在」对外同形。错码/缺码统一回 ErrResetCodeInvalid/ErrResetCodeRequired，
// 不暴露标识是否存在；唯有持有「发往该标识的有效码」者（即标识所有者）越过码闸后，才可能见到
// ErrNoLocalIdentity 友好拒绝（oauth-only / 无本地标识），这不构成对他人账号的枚举。
// 失败按 identifier(=发码目标)+IP 计入 pwreset 作用域 RateLimiter，触顶锁定，成功清零。
// 返回 firstSet：true 表示此前无密码（首设），false 表示替换既有密码（重置）。
func (s *PasswordService) ForgotPassword(ctx context.Context, identifier, code, encryptedB64, ip string) (firstSet bool, err error) {
	dest := identifier

	// 先查锁定（pwreset 作用域，与登录锁独立）：触顶直接拒，省去解密/验码开销。
	locked, err := s.limiter.IsLocked(ctx, auth.ScopePasswordReset, dest, ip)
	if err != nil {
		return false, fmt.Errorf("查询忘记密码锁定状态失败: %w", err)
	}
	if locked {
		return false, ErrResetLocked
	}

	// 缺码不计失败（纯漏填，非爆破）：直接提示需验证码。
	if code == "" {
		return false, ErrResetCodeRequired
	}

	// 解密与策略校验先于验码（用户输入纠错，不应消费 OTP、也不算爆破失败）。
	plain, err := s.rsa.Decrypt(encryptedB64)
	if err != nil {
		return false, ErrInvalidCiphertext
	}
	if err := auth.ValidatePassword(plain); err != nil {
		return false, err // 透传 auth.ErrPassword* 哨兵
	}

	// 验证 pwreset 验证码（用途隔离：login 码命名空间不同自然不通过）；命中即消费（单码一次性）。
	ok, err := s.otp.Verify(ctx, dest, code, auth.PurposePasswordReset)
	if err != nil {
		return false, fmt.Errorf("校验忘记密码验证码失败: %w", err)
	}
	if !ok {
		return false, s.recordResetFailure(ctx, dest, ip)
	}

	// 码已验过（标识所有者已证明）：解析标识 → 本地身份 → User。无本地身份（不存在 / oauth-only）→ 友好拒绝。
	id, found, err := s.identities.FindByTypeIdentifier(ctx, identityType(identifier), identifier)
	if err != nil {
		return false, fmt.Errorf("解析忘记密码标识失败: %w", err)
	}
	if !found || id.Provider != "" {
		return false, ErrNoLocalIdentity
	}

	locals, err := s.identities.ListLocalByUserUUID(ctx, id.UserUUID)
	if err != nil {
		return false, fmt.Errorf("查询本地身份失败: %w", err)
	}
	if len(locals) == 0 {
		return false, ErrNoLocalIdentity
	}
	firstSet = !hasAnySecret(locals)

	hash, err := s.hasher.Hash(plain)
	if err != nil {
		return false, fmt.Errorf("散列密码失败: %w", err)
	}
	if err := s.writeAccountSecret(ctx, id.UserUUID, hash); err != nil {
		return false, err
	}

	// 成功：清零忘记密码失败计数（best-effort，secret 已落库）。
	_ = s.limiter.ResetFailures(ctx, auth.ScopePasswordReset, dest, ip)
	return firstSet, nil
}

// writeAccountSecret 在事务内把新 bcrypt hash 写入该 User 名下所有本地身份（账号级密码）。
// rows==0 视为与前置 List 之间的并发删除等异常，不静默成功。首设与改密路径共用。
func (s *PasswordService) writeAccountSecret(ctx context.Context, userUUID, hash string) error {
	return s.tx.WithinTx(ctx, func(ctx context.Context) error {
		rows, err := s.identities.UpdateSecretByUserUUID(ctx, userUUID, hash)
		if err != nil {
			return fmt.Errorf("写入密码失败: %w", err)
		}
		if rows == 0 {
			return ErrNoLocalIdentity
		}
		return nil
	})
}

// recordResetFailure 记一次改密验证码失败（作用域 pwreset，identifier+IP）；
// 若本次触顶锁定则返回锁定错误，否则返回验证码错误。
func (s *PasswordService) recordResetFailure(ctx context.Context, dest, ip string) error {
	if err := s.limiter.RecordFailure(ctx, auth.ScopePasswordReset, dest, ip); err != nil {
		return fmt.Errorf("记录改密失败失败: %w", err)
	}
	if locked, err := s.limiter.IsLocked(ctx, auth.ScopePasswordReset, dest, ip); err == nil && locked {
		return ErrResetLocked
	}
	return ErrResetCodeInvalid
}

// ChannelForIdentifier 由标识推断 OTP 发送渠道（email/sms），供登出态忘记密码发码端点使用。
// 复用 identityType 的同一 `@` 判别，保持身份类型与发送渠道的推断单一真相源（不在 handler 另立判别）。
func (s *PasswordService) ChannelForIdentifier(identifier string) string {
	if identityType(identifier) == model.IdentityTypeEmail {
		return model.ProviderCategoryEmail
	}
	return model.ProviderCategorySMS
}

// identityType 由标识形态推断身份类型：含 `@` 视为 email，否则 phone。与登录页「邮箱或手机号」
// 单输入框约定一致——登出态忘记密码页同样让用户在一个框里填邮箱或手机号。
// 注意：标识全程按原样使用（不 trim/小写化），与登录/注册路径（signin/*_method.go）一致——
// 防枚举要求登出态错误反馈与现有登录策略同形，故不在此单独引入规范化，避免与既有 raw 标识解析漂移。
func identityType(identifier string) string {
	if strings.Contains(identifier, "@") {
		return model.IdentityTypeEmail
	}
	return model.IdentityTypePhone
}

// preferredLocal 选改密/预填的目标本地身份：优先 email，否则首个本地标识。调用方须保证 locals 非空。
func preferredLocal(locals []model.Identity) model.Identity {
	for _, id := range locals {
		if id.Type == model.IdentityTypeEmail {
			return id
		}
	}
	return locals[0]
}

// preferredIdentifier 选预填标识：优先 email，否则首个本地标识。
func preferredIdentifier(locals []model.Identity) string {
	if len(locals) == 0 {
		return ""
	}
	return preferredLocal(locals).Identifier
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
