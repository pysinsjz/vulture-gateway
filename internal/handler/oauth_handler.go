package handler

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

var (
	errMissingRedirect = errors.New("缺失 redirect_uri")
	errBadRedirect     = errors.New("redirect_uri 必须是 http://127.0.0.1:<port>/callback 或 http://[::1]:<port>/callback")
)

// OAuthHandler 实现网关作为 OAuth 授权服务器的浏览器侧端点（A1 上半）：
// /oauth/authorize 发起、暂存授权请求后 302 跳网关自渲染登录页（ADR-0013：内聚自建身份认证）。
// 登录页提交与 GW_CODE 签发由 LoginHandler 承接（Phase 1 阶段五）。
type OAuthHandler struct {
	authz    *auth.AuthzStore
	gwcodes  *auth.GWCodeStore
	users    dao.UserRepository
	tokenSvc *service.OAuthService
	clientID string // 期望的桌面端 client_id（vulture-desktop）
}

// NewOAuthHandler 构造 handler。
func NewOAuthHandler(authz *auth.AuthzStore, gwcodes *auth.GWCodeStore, users dao.UserRepository, tokenSvc *service.OAuthService, clientID string) *OAuthHandler {
	return &OAuthHandler{authz: authz, gwcodes: gwcodes, users: users, tokenSvc: tokenSvc, clientID: clientID}
}

// Authorize 浏览器入口：校验参数 → 暂存 state/challenge/redirect_uri → 302 跳网关登录页。
//
//	GET /oauth/authorize  (公开)
func (h *OAuthHandler) Authorize(c *gin.Context) {
	q := c.Request.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	codeChallenge := q.Get("code_challenge")
	ccMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	redirectURI := q.Get("redirect_uri")

	if responseType != "code" {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "response_type 必须为 code")
		return
	}
	if clientID != h.clientID {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthUnauthorizedClient, "未知 client_id")
		return
	}
	if codeChallenge == "" || ccMethod != "S256" {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "需要 code_challenge 且 code_challenge_method=S256")
		return
	}
	if state == "" {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "缺失 state")
		return
	}
	if err := validateLoopbackRedirectURI(redirectURI); err != nil {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, err.Error())
		return
	}

	linkedState := idgen.New("st")
	if err := h.authz.Save(c.Request.Context(), linkedState, auth.AuthzRequest{
		OrigState:     state,
		CodeChallenge: codeChallenge,
		RedirectURI:   redirectURI,
	}); err != nil {
		apierror.AbortOAuth(c, http.StatusInternalServerError, apierror.OAuthServerError, "暂存授权请求失败")
		return
	}

	// 302 跳网关自渲染登录页，凭 linkedState 续接已暂存的授权请求（登录提交在 LoginHandler）。
	c.Redirect(http.StatusFound, "/oauth/login?lk="+url.QueryEscape(linkedState))
}

// renderErrorPage 渲染极简浏览器错误页（不回跳，避免向未知地址回送数据）。
func renderErrorPage(c *gin.Context, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusBadRequest,
		"<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\"><title>登录失败</title></head>"+
			"<body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto;text-align:center\">"+
			"<h1>登录失败</h1><p>%s</p></body></html>", message)
}

type tokenRequest struct {
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Device       struct {
		Name       string `json:"name"`
		OS         string `json:"os"`
		AppVersion string `json:"app_version"`
	} `json:"device"`
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	DeviceID     string `json:"device_id"`
}

// Token 令牌端点：按 grant_type 分流。authorization_code（A1 下半，#12）；refresh_token 待 #13。
//
//	POST /oauth/token  (公共客户端 + PKCE)
func (h *OAuthHandler) Token(c *gin.Context) {
	var req tokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, err.Error())
		return
	}

	switch req.GrantType {
	case "authorization_code":
		h.tokenAuthorizationCode(c, req)
	case "refresh_token":
		h.tokenRefresh(c, req)
	default:
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "未知 grant_type")
	}
}

func (h *OAuthHandler) tokenRefresh(c *gin.Context, req tokenRequest) {
	if req.ClientID != h.clientID {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidClient, "未知 client_id")
		return
	}
	if req.RefreshToken == "" {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "缺失 refresh_token")
		return
	}

	res, err := h.tokenSvc.ExchangeRefreshToken(c.Request.Context(), req.RefreshToken)
	// 注：refresh 失败按 auth.md / 错误矩阵返回 401（偏离 RFC 6749 的 400），
	// 使桌面端 401 拦截器触发重登（与 authorization_code 的 400 不同）。
	if errors.Is(err, service.ErrInvalidGrant) {
		apierror.AbortOAuth(c, http.StatusUnauthorized, apierror.OAuthInvalidGrant, "refresh token 无效/已过期/已复用")
		return
	}
	if err != nil {
		apierror.AbortOAuth(c, http.StatusInternalServerError, apierror.OAuthServerError, "刷新失败")
		return
	}

	c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  res.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    res.ExpiresIn,
		RefreshToken: res.RefreshToken,
		DeviceID:     res.DeviceID,
	})
}

func (h *OAuthHandler) tokenAuthorizationCode(c *gin.Context, req tokenRequest) {
	// 公共客户端 vulture-desktop 无 client_secret，仅校验 client_id。
	if req.ClientID != h.clientID {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidClient, "未知 client_id")
		return
	}

	res, err := h.tokenSvc.ExchangeAuthorizationCode(c.Request.Context(), service.ExchangeCodeInput{
		Code:         req.Code,
		CodeVerifier: req.CodeVerifier,
		RedirectURI:  req.RedirectURI,
		Device:       service.DeviceMeta{Name: req.Device.Name, OS: req.Device.OS, AppVersion: req.Device.AppVersion},
	})
	if errors.Is(err, service.ErrInvalidGrant) {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidGrant, "GW_CODE / PKCE / redirect_uri 校验失败")
		return
	}
	if err != nil {
		apierror.AbortOAuth(c, http.StatusInternalServerError, apierror.OAuthServerError, "令牌签发失败")
		return
	}

	c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  res.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    res.ExpiresIn,
		RefreshToken: res.RefreshToken,
		DeviceID:     res.DeviceID,
	})
}

// redirectBack 以 302 跳回桌面端回环地址，附加查询参数。
func redirectBack(c *gin.Context, base string, params url.Values) {
	u, err := url.Parse(base)
	if err != nil {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "回跳地址非法")
		return
	}
	u.RawQuery = params.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// validateLoopbackRedirectURI 按 RFC 8252：host ∈ {127.0.0.1, ::1}、path=/callback，端口任意。
func validateLoopbackRedirectURI(raw string) error {
	if raw == "" {
		return errMissingRedirect
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errBadRedirect
	}
	if u.Scheme != "http" {
		return errBadRedirect
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "::1" {
		return errBadRedirect
	}
	if u.Path != "/callback" {
		return errBadRedirect
	}
	return nil
}
