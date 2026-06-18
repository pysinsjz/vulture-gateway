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

// PluginHandler 实现 plugin 列表/详情/版本（/api/v1/plugins/*，经网关鉴权后转发内网 ClawHub，#19/#20）。
// 管理 API 族：RESTful 真实状态码 + ApiError（ADR-0011）。
type PluginHandler struct {
	svc *service.PluginService
}

// NewPluginHandler 构造 handler。
func NewPluginHandler(svc *service.PluginService) *PluginHandler {
	return &PluginHandler{svc: svc}
}

// ListPlugins 列出 plugin（无搜索，sort+游标+filter + X-Platform/X-App-Version 兼容过滤）。
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
	limit, ok := parseLimit(c)
	if !ok {
		return
	}
	params.Limit = limit

	page, err := h.svc.ListPlugins(c.Request.Context(), params, compatFromHeaders(c))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

// GetPlugin 返回 plugin 详情（含 latestVersion，升级比较用）。
//
//	GET /api/v1/plugins/{name}  (Bearer)
func (h *PluginHandler) GetPlugin(c *gin.Context) {
	detail, err := h.svc.GetPlugin(c.Request.Context(), c.Param("name"))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// GetPluginVersion 返回 plugin 指定版本详情（含 artifact.sha256）。
//
//	GET /api/v1/plugins/{name}/versions/{version}  (Bearer)
func (h *PluginHandler) GetPluginVersion(c *gin.Context) {
	detail, err := h.svc.GetPluginVersion(c.Request.Context(), c.Param("name"), c.Param("version"))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// parseLimit 解析可选的 limit query。非负整数校验失败时写 400 并返回 ok=false。
func parseLimit(c *gin.Context) (int, bool) {
	raw := c.Query("limit")
	if raw == "" {
		return 0, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "limit 必须为非负整数")
		return 0, false
	}
	return limit, true
}

// compatFromHeaders 从 X-Platform / X-App-Version 头构造兼容过滤上下文（§3.7）。
func compatFromHeaders(c *gin.Context) service.CompatContext {
	return service.CompatContext{
		Platform:   c.GetHeader("X-Platform"),
		AppVersion: c.GetHeader("X-App-Version"),
	}
}

// writeClawHubError 把转发层错误按 ADR-0011 重映射为 ApiError。
// ClawHub 返回的 4xx 客户端可纠正错误（含 404 不存在、410 软删除、423/409 pending）透传其
// 状态码与 code；传输失败 / 5xx 收敛为 502 upstream_unavailable，不泄露 ClawHub 内部细节。
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
