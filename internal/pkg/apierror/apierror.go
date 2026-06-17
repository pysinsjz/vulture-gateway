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
	// CodeUnauthorized 鉴权失败：缺失/非法/过期/签名错误的 token，或 token_version 不匹配（即时吊销）。
	CodeUnauthorized = "unauthorized"
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
	OAuthInvalidRequest     = "invalid_request"
	OAuthUnauthorizedClient = "unauthorized_client"
	OAuthServerError        = "server_error"
)

// AbortOAuth 写入状态码 + OAuthError 并中止 gin 处理链。
func AbortOAuth(c *gin.Context, status int, code, description string) {
	c.AbortWithStatusJSON(status, OAuthError{Code: code, Description: description})
}
