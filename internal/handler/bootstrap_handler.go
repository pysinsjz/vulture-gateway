package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// BootstrapHandler 实现启动引导聚合端点（/api/v1/bootstrap，#28）。
// 公开例外：不要求 Bearer、内容均非用户态（见 DefaultPublicPaths）。错误用 ApiError（ADR-0011）。
type BootstrapHandler struct {
	svc *service.BootstrapService
}

// NewBootstrapHandler 构造 handler。
func NewBootstrapHandler(svc *service.BootstrapService) *BootstrapHandler {
	return &BootstrapHandler{svc: svc}
}

// Bootstrap 返回启动握手聚合信息，支持 (channel, X-App-Version, X-Platform) 分桶 ETag + If-None-Match → 304。
//
//	GET /api/v1/bootstrap  (公开)
//
// 必填头 X-App-Version / X-Platform；可选 query channel（缺省 stable）、轮询头 If-None-Match。
func (h *BootstrapHandler) Bootstrap(c *gin.Context) {
	appVersion := c.GetHeader("X-App-Version")
	platform := c.GetHeader("X-Platform")
	if appVersion == "" || platform == "" {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "缺少必填头 X-App-Version 或 X-Platform")
		return
	}

	channel := c.Query("channel")
	if channel == "" {
		channel = service.ChannelStable
	}
	if !service.IsValidChannel(channel) {
		apierror.Abort(c, http.StatusBadRequest, "invalid_channel", "非法 channel: "+channel)
		return
	}

	resp, etag := h.svc.Build(channel, appVersion, platform, time.Now())
	c.Header("ETag", etag)

	// 轮询缓存协商：同桶同内容 → 304 空体。
	if c.GetHeader("If-None-Match") == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.JSON(http.StatusOK, resp)
}
