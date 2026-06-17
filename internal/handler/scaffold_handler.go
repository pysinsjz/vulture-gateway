package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
)

// ScaffoldHandler 提供脚手架内部端点（/__dev/*），仅 dev/test 挂载，用于 #9 端到端验证。
// 它替代尚未实现的真实登录流程（A1），内部签发 access JWT 并初始化 / bump token_version，
// 从而驱动 JWTAuth 与即时吊销逻辑的端到端验证。生产环境不挂载。
type ScaffoldHandler struct {
	signer *auth.Signer
	tvs    *auth.TokenVersionStore
}

// NewScaffoldHandler 构造脚手架 handler。
func NewScaffoldHandler(signer *auth.Signer, tvs *auth.TokenVersionStore) *ScaffoldHandler {
	return &ScaffoldHandler{signer: signer, tvs: tvs}
}

type issueTokenRequest struct {
	Sub          string `json:"sub" binding:"required"`
	DeviceID     string `json:"device_id" binding:"required"`
	TokenVersion *int64 `json:"token_version"` // 可选，默认 1
}

type issueTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	DeviceID     string `json:"device_id"`
	TokenVersion int64  `json:"token_version"`
}

// IssueToken 内部签发一枚 access JWT，并把该 Device 的 token_version 初始化为同值。
//
//	POST /__dev/token  {sub, device_id, token_version?}
func (h *ScaffoldHandler) IssueToken(c *gin.Context) {
	var req issueTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	version := int64(1)
	if req.TokenVersion != nil {
		version = *req.TokenVersion
	}

	if err := h.tvs.Set(c.Request.Context(), req.DeviceID, version); err != nil {
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	token, err := h.signer.Issue(req.Sub, req.DeviceID, version)
	if err != nil {
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	c.JSON(http.StatusOK, issueTokenResponse{
		AccessToken:  token,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.signer.TTL().Seconds()),
		DeviceID:     req.DeviceID,
		TokenVersion: version,
	})
}

type bumpRequest struct {
	DeviceID string `json:"device_id" binding:"required"`
}

// BumpDevice 自增指定 Device 的 token_version，模拟登出/吊销，使其在途 access JWT 立即失效。
//
//	POST /__dev/bump  {device_id}
func (h *ScaffoldHandler) BumpDevice(c *gin.Context) {
	var req bumpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Abort(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	version, err := h.tvs.Bump(c.Request.Context(), req.DeviceID)
	if err != nil {
		apierror.Abort(c, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"device_id": req.DeviceID, "token_version": version})
}
