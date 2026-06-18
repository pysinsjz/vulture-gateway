package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// PluginHandler 实现 plugin 列表等管理 API（/api/v1/plugins，经网关鉴权后转发内网 ClawHub，#19）。
// 管理 API 族：RESTful 真实状态码 + ApiError（ADR-0011）。
type PluginHandler struct {
	svc *service.PluginService
}

// NewPluginHandler 构造 handler。
func NewPluginHandler(svc *service.PluginService) *PluginHandler {
	return &PluginHandler{svc: svc}
}

// ListPlugins 列出 plugin（无搜索，sort+游标+filter），数据经 ClawHub /packages 翻译而来。
//
//	GET /api/v1/plugins?limit=&cursor=&sort=&family=&channel=&category=  (Bearer)
func (h *PluginHandler) ListPlugins(c *gin.Context) {
	params := service.PluginListParams{
		Cursor:   c.Query("cursor"),
		Sort:     c.Query("sort"),
		Family:   c.Query("family"),
		Channel:  c.Query("channel"),
		Category: c.Query("category"),
	}
	if raw := c.Query("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 {
			apierror.Abort(c, http.StatusBadRequest, "invalid_request", "limit 必须为非负整数")
			return
		}
		params.Limit = limit
	}

	page, err := h.svc.ListPlugins(c.Request.Context(), params)
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

// writeClawHubError 把转发层错误按 ADR-0011 重映射为 ApiError。
// ClawHub 返回的 4xx 客户端可纠正错误透传其状态码与 code；传输失败 / 5xx 收敛为 502 upstream_unavailable。
func writeClawHubError(c *gin.Context, err error) {
	var hubErr *clawhub.Error
	if errors.As(err, &hubErr) && hubErr.Status >= 400 && hubErr.Status < 500 {
		code := hubErr.Code
		if code == "" {
			code = "upstream_error"
		}
		apierror.Abort(c, hubErr.Status, code, hubErr.Message)
		return
	}
	apierror.Abort(c, http.StatusBadGateway, "upstream_unavailable", "注册中心暂时不可用")
}
