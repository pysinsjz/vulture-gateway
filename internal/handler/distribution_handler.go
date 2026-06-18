package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// DistributionHandler 实现宿主 App 自更新公开端点（/api/v1/app/latest，#27）。
// 管理 API 族：真实状态码 + ApiError（ADR-0011）。公开例外：不要求 Bearer（见 DefaultPublicPaths）。
type DistributionHandler struct {
	svc *service.DistributionService
}

// NewDistributionHandler 构造 handler。
func NewDistributionHandler(svc *service.DistributionService) *DistributionHandler {
	return &DistributionHandler{svc: svc}
}

// AppLatestResponse 是 app/latest 响应。update_available=false 时仅 latest_version 有意义。
type AppLatestResponse struct {
	UpdateAvailable bool   `json:"update_available"`
	LatestVersion   string `json:"latest_version"`
	Mandatory       bool   `json:"mandatory"`
	DownloadURL     string `json:"download_url,omitempty"`
	Checksum        string `json:"checksum,omitempty"`
	Size            int64  `json:"size,omitempty"`
	ReleaseNotes    string `json:"release_notes,omitempty"`
}

// AppLatest 宿主 App 自更新检查（公开，无需登录）。按 (channel, platform) 解析最新发布，
// 与 current_version 比较给出更新摘要。mandatory 仅提示，网关不做版本硬门禁。
//
//	GET /api/v1/app/latest?platform=&channel=&current_version=  (公开)
//
// platform/current_version 缺省回退 X-Platform/X-App-Version 公共头；channel 缺省 stable。
func (h *DistributionHandler) AppLatest(c *gin.Context) {
	platform := firstNonEmpty(c.Query("platform"), c.GetHeader("X-Platform"))
	if platform == "" {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "缺少 platform")
		return
	}
	if !service.IsValidPlatform(platform) {
		apierror.Abort(c, http.StatusBadRequest, "invalid_platform", "非法 platform: "+platform)
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

	current := firstNonEmpty(c.Query("current_version"), c.GetHeader("X-App-Version"))
	if current == "" {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "缺少 current_version")
		return
	}

	res, err := h.svc.Resolve(channel, platform, current)
	if err != nil {
		if errors.Is(err, service.ErrNoRelease) {
			apierror.Abort(c, http.StatusNotFound, "no_release", "该平台/渠道暂无发布")
			return
		}
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", "解析发布失败")
		return
	}

	c.JSON(http.StatusOK, toAppLatestResponse(res))
}

// toAppLatestResponse 把判定结果映射为响应体。无更新时只回 latest_version。
func toAppLatestResponse(res *service.ResolveResult) AppLatestResponse {
	if res.Update == nil {
		return AppLatestResponse{UpdateAvailable: false, LatestVersion: res.LatestVersion}
	}
	u := res.Update
	return AppLatestResponse{
		UpdateAvailable: true,
		LatestVersion:   u.LatestVersion,
		Mandatory:       u.Mandatory,
		DownloadURL:     u.DownloadURL,
		Checksum:        u.Checksum,
		Size:            u.Size,
		ReleaseNotes:    u.ReleaseNotes,
	}
}

// firstNonEmpty 返回首个非空字符串。
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
