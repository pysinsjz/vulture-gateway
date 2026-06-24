// Package handler 提供 HTTP 处理层。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// ProbeHandler 提供受保护探针端点与公开例外端点的占位实现，用于验证鉴权链路通畅。
type ProbeHandler struct {
	identities dao.IdentityRepository
}

// NewProbeHandler 构造探针 handler。
func NewProbeHandler(identities dao.IdentityRepository) *ProbeHandler {
	return &ProbeHandler{identities: identities}
}

// Whoami 受保护探针：返回 JWTAuth 从 token 解析出的 sub / device_id，并回查该用户的邮箱，
// 证明鉴权链路通畅。sub 即 User 的 uuid（见 ADR-0013），邮箱取自该 User 的 email 类型 Identity。
//
// 邮箱回查为尽力而为：未绑定邮箱或回查出错时返回空字符串（出错经 c.Error 记录，由日志中间件呈现），
// 不影响探针对鉴权链路的核心断言。
//
//	GET /api/v1/whoami  (Bearer)
func (h *ProbeHandler) Whoami(c *gin.Context) {
	sub := c.GetString(middleware.CtxKeySub)

	email := ""
	if identity, found, err := h.identities.FindByUserUUIDAndType(c.Request.Context(), sub, model.IdentityTypeEmail); err != nil {
		_ = c.Error(err)
	} else if found {
		email = identity.Identifier
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":       sub,
		"device_id": c.GetString(middleware.CtxKeyDeviceID),
		"email":     email,
	})
}
