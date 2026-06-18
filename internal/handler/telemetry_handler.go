package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// TelemetryHandler 实现安装遥测上报（/api/v1/telemetry/install，转发内网 ClawHub，#22）。
type TelemetryHandler struct {
	svc *service.TelemetryService
}

// NewTelemetryHandler 构造 handler。
func NewTelemetryHandler(svc *service.TelemetryService) *TelemetryHandler {
	return &TelemetryHandler{svc: svc}
}

// ReportInstall 上报安装遥测（best-effort）。ClawHub 按 root 状态快照对账，重复上报幂等收敛。
// 上游转发失败也静默成功（返回 {ok:true}），避免客户端重试风暴；遥测本就 best-effort。
//
//	POST /api/v1/telemetry/install  (Bearer)
func (h *TelemetryHandler) ReportInstall(c *gin.Context) {
	var report service.TelemetryReport
	if err := c.ShouldBindJSON(&report); err != nil {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", "遥测上报体格式错误")
		return
	}

	_ = h.svc.ReportInstall(c.Request.Context(), report)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
