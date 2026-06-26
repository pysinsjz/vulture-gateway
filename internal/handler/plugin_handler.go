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
	dl  *downloadProxy
}

// NewPluginHandler 构造 handler。dl 用于把内网 ClawHub 的制品字节代理回传桌面端（见 downloadProxy）。
func NewPluginHandler(svc *service.PluginService, dl *downloadProxy) *PluginHandler {
	return &PluginHandler{svc: svc, dl: dl}
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

// PluginCategories 返回 plugin 浏览分类 + 计数（驱动桌面端分组标题与计数，§3.1b）。
// 网关派生：聚合全量 /packages 列表，按 X-Platform/X-App-Version 兼容过滤后按 pluginCategory 计数。
//
//	GET /api/v1/plugins/categories  (Bearer)
func (h *PluginHandler) PluginCategories(c *gin.Context) {
	res, err := h.svc.PluginCategories(c.Request.Context(), compatFromHeaders(c))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
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

// ListPluginVersions 返回 plugin 版本历史（游标分页）。
//
//	GET /api/v1/plugins/{name}/versions?limit=&cursor=  (Bearer)
func (h *PluginHandler) ListPluginVersions(c *gin.Context) {
	limit, ok := parseLimit(c)
	if !ok {
		return
	}
	page, err := h.svc.ListPluginVersions(
		c.Request.Context(),
		c.Param("name"),
		service.PageParams{Limit: limit, Cursor: c.Query("cursor")},
	)
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
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

// DownloadPlugin 下载 plugin（legacy-zip）：网关反代 ClawHub 流式端点 GET {base}/packages/{name}/download?version=，
// 把字节透传回桌面端（interim 路线 A，见 downloadProxy；待路线 B 改直接 302 到 MinIO 公网）。
// 安全门由 ClawHub 在流式端点内强制（getReleaseSecurityBlock → 403/410/451），反代时原样透传状态码。
//
//	GET /api/v1/plugins/{name}/download?version=  (Bearer)
func (h *PluginHandler) DownloadPlugin(c *gin.Context) {
	h.dl.stream(c, h.svc.DownloadStreamURL(c.Param("name"), c.Query("version")))
}

// DownloadPluginArtifact 下载 plugin（npm-pack .tgz）：反代 ClawHub
// GET {base}/packages/{name}/versions/{version}/artifact/download，同 DownloadPlugin。
//
//	GET /api/v1/plugins/{name}/versions/{version}/artifact/download  (Bearer)
func (h *PluginHandler) DownloadPluginArtifact(c *gin.Context) {
	h.dl.stream(c, h.svc.ArtifactStreamURL(c.Param("name"), c.Param("version")))
}

// PluginSecurity 单查 plugin 版本的安装阻断信号（PluginTrust，blockedFromDownload 权威）。
//
//	GET /api/v1/plugins/{name}/versions/{version}/security  (Bearer)
func (h *PluginHandler) PluginSecurity(c *gin.Context) {
	trust, err := h.svc.PluginSecurity(c.Request.Context(), c.Param("name"), c.Param("version"))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, trust)
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
