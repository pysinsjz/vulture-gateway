package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// SkillHandler 实现 skill 列表/详情/版本/resolve（/api/v1/skills/*，经网关转发内网 ClawHub，#20）。
// 管理 API 族：RESTful 真实状态码 + ApiError（ADR-0011）。
type SkillHandler struct {
	svc *service.SkillService
	dl  *downloadProxy
}

// NewSkillHandler 构造 handler。dl 用于把内网 ClawHub 的制品字节代理回传桌面端（见 downloadProxy）。
func NewSkillHandler(svc *service.SkillService, dl *downloadProxy) *SkillHandler {
	return &SkillHandler{svc: svc, dl: dl}
}

// ListSkills 列出 skill（无搜索，sort+游标+category filter + X-Platform 平台过滤）。
//
//	GET /api/v1/skills?limit=&cursor=&sort=&category=  (Bearer)
func (h *SkillHandler) ListSkills(c *gin.Context) {
	limit, ok := parseLimit(c)
	if !ok {
		return
	}
	params := service.SkillListParams{
		Limit:    limit,
		Cursor:   c.Query("cursor"),
		Sort:     c.Query("sort"),
		Category: c.Query("category"),
	}

	page, err := h.svc.ListSkills(c.Request.Context(), params, compatFromHeaders(c))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

// SkillCategories 返回 skill 浏览分类 + 计数（驱动桌面端分组标题与计数，§3.1b）。
// 网关派生：聚合全量 /skills 列表，按 X-Platform 兼容过滤后按 category 计数。
// 须在路由上声明于 /skills/:slug 之前语义上的同级静态段（categories 非 slug）。
//
//	GET /api/v1/skills/categories  (Bearer)
func (h *SkillHandler) SkillCategories(c *gin.Context) {
	res, err := h.svc.SkillCategories(c.Request.Context(), compatFromHeaders(c))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// GetSkill 返回 skill 详情。
//
//	GET /api/v1/skills/{slug}  (Bearer)
func (h *SkillHandler) GetSkill(c *gin.Context) {
	detail, err := h.svc.GetSkill(c.Request.Context(), c.Param("slug"))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// ListSkillVersions 返回 skill 版本历史（游标分页）。
//
//	GET /api/v1/skills/{slug}/versions?limit=&cursor=  (Bearer)
func (h *SkillHandler) ListSkillVersions(c *gin.Context) {
	limit, ok := parseLimit(c)
	if !ok {
		return
	}
	page, err := h.svc.ListSkillVersions(c.Request.Context(), c.Param("slug"), service.PageParams{Limit: limit, Cursor: c.Query("cursor")})
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

// GetSkillVersion 返回 skill 指定版本详情（含 artifact.sha256）。
//
//	GET /api/v1/skills/{slug}/versions/{version}  (Bearer)
func (h *SkillHandler) GetSkillVersion(c *gin.Context) {
	detail, err := h.svc.GetSkillVersion(c.Request.Context(), c.Param("slug"), c.Param("version"))
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// ResolveSkill 把本地指纹映射到已发布版本（skill 更新检测，§3.4）。hash 须为 64 位 hex。
//
//	GET /api/v1/skills/{slug}/resolve?hash=  (Bearer)
func (h *SkillHandler) ResolveSkill(c *gin.Context) {
	hash := c.Query("hash")
	if !isHex64(hash) {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "hash 必须为 64 位十六进制指纹")
		return
	}

	res, err := h.svc.ResolveSkill(c.Request.Context(), c.Param("slug"), hash)
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// DownloadSkill 下载 skill：网关反代 ClawHub 流式下载端点 GET {base}/download?slug=&version=，
// 把字节透传回桌面端（interim 路线 A，见 downloadProxy；待路线 B 改直接 302 到 MinIO 公网）。
// version 为空取 latest。安全门由 ClawHub 在流式端点内强制（decision=fail / 文件访问门 → 403/410/451），
// 反代时原样透传该状态码。
//
//	GET /api/v1/skills/{slug}/download?version=  (Bearer)
func (h *SkillHandler) DownloadSkill(c *gin.Context) {
	h.dl.stream(c, h.svc.DownloadStreamURL(c.Param("slug"), c.Query("version")))
}

// SecurityVerdicts 批量查询 skill 安全裁决（1–100 项）。
//
//	POST /api/v1/skills/-/security-verdicts  (Bearer)
func (h *SkillHandler) SecurityVerdicts(c *gin.Context) {
	var body struct {
		Items []service.VerdictQuery `json:"items" binding:"required,min=1,max=100,dive"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "items 必须为 1–100 项，每项含 slug 与 version")
		return
	}

	res, err := h.svc.SecurityVerdicts(c.Request.Context(), body.Items)
	if err != nil {
		writeClawHubError(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// isHex64 校验字符串为 64 位十六进制（指纹格式）。
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
