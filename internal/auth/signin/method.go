// Package signin 收纳所有登录方式（SigninMethod）于单一接口 + Kind 派发 + registry（ADR-0013）。
// Phase 1 仅实现 Direct 三方式（password/email_code/sms_code）；Redirect 抽象保留定义无实现，
// 作为未来从 Casdoor 迁移社会化登录 provider 的接入点。
package signin

import (
	"context"
	"errors"
	"strings"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// Kind 区分登录方式的执行路径。
type Kind int

const (
	// KindDirect 本地校验：登录页直接收凭据，走 Verify。
	KindDirect Kind = iota
	// KindRedirect 跳外部 IdP：走 AuthorizeURL + Exchange（Phase 1 无实现）。
	KindRedirect
)

// 业务错误（登录失败语义）。handler 据此渲染提示，且对外不区分「账号不存在/密码错」以防枚举。
var (
	// ErrInvalidCredentials 标识/密码不匹配，或账号不存在、未设密码（合并以防账号枚举）。
	ErrInvalidCredentials = errors.New("标识或密码错误")
	// ErrInvalidCode 验证码错误或已失效。
	ErrInvalidCode = errors.New("验证码错误或已失效")
	// ErrAccountLocked 失败过多被临时锁定。
	ErrAccountLocked = errors.New("尝试过于频繁，请稍后再试")
	// ErrNotRedirect Direct 方式不支持 Redirect 侧操作（AuthorizeURL/Exchange）。
	ErrNotRedirect = errors.New("该登录方式不支持重定向授权")
)

// VerifyInput 是本地登录方式校验所需的入参。
type VerifyInput struct {
	Identifier string // 登录标识：邮箱或手机号
	Credential string // 凭据：密码（RSA 密文）或验证码（明文）
	IP         string // 来源 IP，用于限流键
}

// SigninMethod 是单一登录方式抽象。登录页遍历同一 list 渲染（Name + Kind），
// 提交时按 Kind 派发：Direct 走 Verify，Redirect 走 AuthorizeURL+Exchange。
type SigninMethod interface {
	// Name 方式名：password / email_code / sms_code / 未来 social provider name。
	Name() string
	// Kind 执行路径。
	Kind() Kind
	// Verify（Direct）本地校验。内部完成 Identity→User 解析（含验证码登录即注册），
	// 返回 User.uuid 作为 subject。失败返回上面的业务错误或系统错误。
	Verify(ctx context.Context, in VerifyInput) (subject string, err error)
	// AuthorizeURL（Redirect）构造跳外部 IdP 的授权 URL。Direct 方式返回 ErrNotRedirect。
	AuthorizeURL(linkedState, nonce string) (string, error)
	// Exchange（Redirect）用外部授权码换取 subject。Direct 方式返回 ErrNotRedirect。
	Exchange(ctx context.Context, code, nonce string) (subject string, err error)
}

// directBase 给 Direct 方式补齐 Redirect 侧方法（永不被调用，返回 ErrNotRedirect）。
// 内嵌它即声明 Kind=Direct，避免每个 Direct 实现重复书写不相关的 Redirect 桩。
type directBase struct{}

func (directBase) Kind() Kind { return KindDirect }
func (directBase) AuthorizeURL(_, _ string) (string, error) {
	return "", ErrNotRedirect
}
func (directBase) Exchange(_ context.Context, _, _ string) (string, error) {
	return "", ErrNotRedirect
}

// classifyIdentifier 按格式判定登录标识类型：含 '@' 视为邮箱，否则视为手机号。
func classifyIdentifier(identifier string) string {
	if strings.Contains(identifier, "@") {
		return model.IdentityTypeEmail
	}
	return model.IdentityTypePhone
}
