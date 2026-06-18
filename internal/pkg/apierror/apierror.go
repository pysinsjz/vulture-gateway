// Package apierror 提供管理 API（/api/v1/*）的统一错误体。
//
// 按 ADR-0011，管理 API 返回真实 HTTP 状态码 + ApiError{error, message}，
// 不使用 web-go 的 200-信封。成功直接返回 JSON 实体或 204。
package apierror

import "github.com/gin-gonic/gin"

// ApiError 是管理 API 的错误响应体。
// Code 走机读分流（桌面端按 error 字段做处理决策），Message 面向人读排障。
type ApiError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

// 常用错误码常量。完整错误矩阵见 docs/flows/api-conventions.md。
const (
	// CodeUnauthorized 鉴权失败：缺失/非法/过期/签名错误的 token。
	CodeUnauthorized = "unauthorized"
	// CodeDeviceRevoked Device 被吊销（token_version 不匹配，即时吊销）。LLM 族据此返 403（见 api-conventions §3）。
	CodeDeviceRevoked = "device_revoked"
)

// New 构造一个 ApiError。
func New(code, message string) ApiError {
	return ApiError{Code: code, Message: message}
}

// Abort 写入状态码 + ApiError 并中止 gin 处理链。
func Abort(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, New(code, message))
}

// OAuthError 是 OAuth 端点（/oauth/*）的错误体，遵循 RFC 6749：{error, error_description}。
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// 常用 OAuth 错误码（RFC 6749）。
const (
	OAuthInvalidRequest       = "invalid_request"
	OAuthUnauthorizedClient   = "unauthorized_client"
	OAuthInvalidClient        = "invalid_client"
	OAuthInvalidGrant         = "invalid_grant"
	OAuthUnsupportedGrantType = "unsupported_grant_type"
	OAuthAccessDenied         = "access_denied"
	OAuthServerError          = "server_error"
)

// AbortOAuth 写入状态码 + OAuthError 并中止 gin 处理链。
func AbortOAuth(c *gin.Context, status int, code, description string) {
	c.AbortWithStatusJSON(status, OAuthError{Code: code, Description: description})
}

// OpenAIError 是 LLM 代理族（/v1/*）的错误体，贴 OpenAI 兼容形态：{error:{message,type,code}}。
// 桌面端对 LLM 族用统一的 OpenAI 错误解析（含网关自身 401/402/403/413/429）。
type OpenAIError struct {
	Error OpenAIErrorBody `json:"error"`
}

// OpenAIErrorBody 是 OpenAI 错误体的内层。
type OpenAIErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

// OpenAI 错误 type 常量。
const (
	OpenAITypeInvalidRequest = "invalid_request_error"
)

// AbortOpenAI 写入状态码 + OpenAIError 并中止 gin 处理链。
func AbortOpenAI(c *gin.Context, status int, typ, code, message string) {
	c.AbortWithStatusJSON(status, OpenAIError{Error: OpenAIErrorBody{Message: message, Type: typ, Code: code}})
}
