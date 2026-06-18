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

// JWTAuth 校验 access JWT 并执行即时吊销比对（ADR-0010）。
//
// 流程：公开例外放行 → 取 Bearer token → 验签/校验有效期 → 与 Redis 中该 Device 当前
// token_version 做一次 O(1) 比对。任意失败返回 401 + ApiError{error, message}。
//
// 注：按 api-conventions.md，「Device 被吊销」语义上对应 403 device_revoked；本切片（#9）
// 按 issue 验收口径将 token_version 不匹配也归为 401，待 A3 设备吊销切片统一口径。
func JWTAuth(verifier *auth.Signer, tvs *auth.TokenVersionStore, publicPaths []string) gin.HandlerFunc {
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
			apierror.Abort(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "缺失或格式错误的 Authorization 头")
			return
		}

		claims, err := verifier.Verify(raw)
		if err != nil {
			apierror.Abort(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "access token 无效或已过期")
			return
		}

		current, exists, err := tvs.Current(c.Request.Context(), claims.DeviceID)
		if err != nil {
			apierror.Abort(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "无法校验 token 状态")
			return
		}
		if !exists || current != claims.TokenVersion {
			apierror.Abort(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "access token 已被吊销")
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
