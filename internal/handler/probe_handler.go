// Package handler 提供 HTTP 处理层。
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/middleware"
)

// ProbeHandler 提供受保护探针端点与公开例外端点的占位实现，用于验证鉴权链路通畅。
type ProbeHandler struct{}

// NewProbeHandler 构造探针 handler。
func NewProbeHandler() *ProbeHandler {
	return &ProbeHandler{}
}

// Whoami 受保护探针：返回 JWTAuth 从 token 解析出的 sub / device_id，证明鉴权链路通畅。
//
//	GET /api/v1/whoami  (Bearer)
func (h *ProbeHandler) Whoami(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"sub":       c.GetString(middleware.CtxKeySub),
		"device_id": c.GetString(middleware.CtxKeyDeviceID),
	})
}
