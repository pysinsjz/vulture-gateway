package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// DeviceHandler 实现 A3 登出与 Device 管理（#14）。管理 API（/api/v1/*，RESTful + ApiError）。
type DeviceHandler struct {
	signer *auth.Signer
	svc    *service.DeviceService
}

// NewDeviceHandler 构造 handler。
func NewDeviceHandler(signer *auth.Signer, svc *service.DeviceService) *DeviceHandler {
	return &DeviceHandler{signer: signer, svc: svc}
}

// Logout 登出：Bearer 有效则吊销该 Device；否则 body refresh_token 兜底。两路均 204。
//
//	POST /api/v1/auth/logout  (公开例外，自带鉴权)
func (h *DeviceHandler) Logout(c *gin.Context) {
	// Bearer 路：用合法签名的 access（即使 token_version 已变也可登出，幂等）取 device_id。
	if raw, ok := middleware.BearerToken(c); ok {
		if claims, err := h.signer.Verify(raw); err == nil {
			if err := h.svc.LogoutByDevice(c.Request.Context(), claims.DeviceID); err != nil {
				apierror.Abort(c, http.StatusInternalServerError, "internal_error", "登出失败")
				return
			}
			c.Status(http.StatusNoContent)
			return
		}
	}

	// 兜底路：access 已失效，按 body refresh_token 吊销其家族。
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.RefreshToken == "" {
		apierror.Abort(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "缺少有效 access 或 refresh_token")
		return
	}
	if err := h.svc.LogoutByRefreshToken(c.Request.Context(), body.RefreshToken); err != nil {
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", "登出失败")
		return
	}
	c.Status(http.StatusNoContent)
}

// ListDevices 列出当前 User 的已授权 Device，标记当前设备。
//
//	GET /api/v1/devices  (Bearer)
func (h *DeviceHandler) ListDevices(c *gin.Context) {
	userUUID := c.GetString(middleware.CtxKeySub)
	currentDevice := c.GetString(middleware.CtxKeyDeviceID)

	views, err := h.svc.ListDevices(c.Request.Context(), userUUID, currentDevice)
	if err != nil {
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", "获取设备列表失败")
		return
	}
	c.JSON(http.StatusOK, views)
}

// DeleteDevice 吊销指定 Device，使其在途 access 即时失效。
//
//	DELETE /api/v1/devices/{device_id}  (Bearer)
func (h *DeviceHandler) DeleteDevice(c *gin.Context) {
	userUUID := c.GetString(middleware.CtxKeySub)
	target := c.Param("device_id")

	err := h.svc.RevokeDevice(c.Request.Context(), userUUID, target)
	if errors.Is(err, service.ErrDeviceNotFound) {
		apierror.Abort(c, http.StatusNotFound, "not_found", "设备不存在")
		return
	}
	if err != nil {
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", "吊销设备失败")
		return
	}
	c.Status(http.StatusNoContent)
}
