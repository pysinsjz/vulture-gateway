// Package middleware 提供 Gin 中间件。
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
)

// Gin context 键：经 JWTAuth 鉴权通过后写入，供下游 handler 读取。
const (
	CtxKeySub      = "sub"
	CtxKeyDeviceID = "device_id"
)

// DefaultPublicPaths 是 JWTAuth 的公开例外路径（不要求 Bearer）。
// bootstrap / app/latest 属其它域；auth/logout 自带鉴权（Bearer 或 body refresh_token 兜底，#14），
// 故在中间件层放行、由 handler 内部自校验。
var DefaultPublicPaths = []string{
	"/api/v1/bootstrap",
	"/api/v1/app/latest",
	"/api/v1/auth/logout",
}

// unauthorizedFunc 写入 401 错误体（按端点族区分形态）。
type unauthorizedFunc func(c *gin.Context, message string)

// managementUnauthorized 管理 API 族（/api/v1/*）：ApiError{error, message}。
func managementUnauthorized(c *gin.Context, message string) {
	apierror.Abort(c, http.StatusUnauthorized, apierror.CodeUnauthorized, message)
}

// llmUnauthorized LLM 代理族（/v1/*）：OpenAI 兼容 {error:{message,type,code}}。
func llmUnauthorized(c *gin.Context, message string) {
	apierror.AbortOpenAI(c, http.StatusUnauthorized, apierror.OpenAITypeInvalidRequest, apierror.CodeUnauthorized, message)
}

// JWTAuth 是管理 API 族（/api/v1/*）的鉴权中间件：失败返回 ApiError。
func JWTAuth(verifier *auth.Signer, tvs *auth.TokenVersionStore, publicPaths []string) gin.HandlerFunc {
	return jwtAuth(verifier, tvs, publicPaths, managementUnauthorized)
}

// JWTAuthLLM 是 LLM 代理族（/v1/*）的鉴权中间件：失败返回 OpenAI 错误体。
// 供 LLM 域（#23+）的 /v1/* 端点使用，使三族错误体在鉴权层即各呈其形（#15）。
func JWTAuthLLM(verifier *auth.Signer, tvs *auth.TokenVersionStore, publicPaths []string) gin.HandlerFunc {
	return jwtAuth(verifier, tvs, publicPaths, llmUnauthorized)
}

// jwtAuth 校验 access JWT 并执行即时吊销比对（ADR-0010）。错误体形态由 onUnauthorized 决定。
//
// 流程：公开例外放行 → 取 Bearer token → 验签/校验有效期 → 与 Redis 中该 Device 当前
// token_version 做一次 O(1) 比对。任意失败返回 401（族特定错误体）。
//
// 注：按 api-conventions.md，「Device 被吊销」语义上对应 403 device_revoked；当前按 issue
// 验收口径将 token_version 不匹配也归为 401，口径统一待后续。
func jwtAuth(verifier *auth.Signer, tvs *auth.TokenVersionStore, publicPaths []string, onUnauthorized unauthorizedFunc) gin.HandlerFunc {
	public := make(map[string]struct{}, len(publicPaths))
	for _, p := range publicPaths {
		public[p] = struct{}{}
	}

	return func(c *gin.Context) {
		if _, ok := public[c.FullPath()]; ok {
			c.Next()
			return
		}

		raw, ok := BearerToken(c)
		if !ok {
			onUnauthorized(c, "缺失或格式错误的 Authorization 头")
			return
		}

		claims, err := verifier.Verify(raw)
		if err != nil {
			onUnauthorized(c, "access token 无效或已过期")
			return
		}

		current, exists, err := tvs.Current(c.Request.Context(), claims.DeviceID)
		if err != nil {
			onUnauthorized(c, "无法校验 token 状态")
			return
		}
		if !exists || current != claims.TokenVersion {
			onUnauthorized(c, "access token 已被吊销")
			return
		}

		c.Set(CtxKeySub, claims.Subject)
		c.Set(CtxKeyDeviceID, claims.DeviceID)
		c.Next()
	}
}

// BearerToken 从 Authorization 头提取 Bearer token。
func BearerToken(c *gin.Context) (string, bool) {
	h := c.GetHeader("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
