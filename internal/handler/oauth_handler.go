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

// OAuthHandler 实现网关作为 OAuth 授权服务器的浏览器侧端点（A1 上半，#11）：
// /oauth/authorize 发起、/oauth/callback/casdoor 上游回调到签发 GW_CODE 为止。
type OAuthHandler struct {
	upstream auth.UpstreamIDP
	authz    *auth.AuthzStore
	gwcodes  *auth.GWCodeStore
	users    dao.UserRepository
	tokenSvc *service.OAuthService
	clientID string // 期望的桌面端 client_id（vulture-desktop）
}

// NewOAuthHandler 构造 handler。
func NewOAuthHandler(upstream auth.UpstreamIDP, authz *auth.AuthzStore, gwcodes *auth.GWCodeStore, users dao.UserRepository, tokenSvc *service.OAuthService, clientID string) *OAuthHandler {
	return &OAuthHandler{upstream: upstream, authz: authz, gwcodes: gwcodes, users: users, tokenSvc: tokenSvc, clientID: clientID}
}

// Authorize 浏览器入口：校验参数 → 暂存 state/challenge/redirect_uri → 302 跳上游。
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

	c.Redirect(http.StatusFound, h.upstream.AuthorizeURL(linkedState))
}

// Callback 上游回调：换 subject → 解析/创建 User → 签发 GW_CODE → 302 回跳桌面端。
// 失败回跳三分支（#15）：state 有效→回跳带 error/state；state 失效→渲染错误页不回跳。
//
//	GET /oauth/callback/casdoor  (上游回调)
func (h *OAuthHandler) Callback(c *gin.Context) {
	linkedState := c.Query("state")
	if linkedState == "" {
		// 无 state，无法定位 redirect_uri → 渲染错误页，不向未知地址回送。
		renderErrorPage(c, "登录状态缺失，请重新发起登录。")
		return
	}

	req, found, err := h.authz.Take(c.Request.Context(), linkedState)
	if err != nil {
		renderErrorPage(c, "登录处理出错，请稍后重试。")
		return
	}
	if !found {
		// state 失效/非法：网关已无 redirect_uri，不回跳。
		renderErrorPage(c, "登录状态无效或已过期，请重新发起登录。")
		return
	}

	// 自此已知 redirect_uri，失败按 RFC 6749 回跳 redirect_uri?error=&error_description=&state=。
	// 上游显式错误（如用户取消）→ access_denied；其余上游/网关交互失败 → server_error。
	if upErr := c.Query("error"); upErr != "" {
		h.redirectError(c, req.RedirectURI, normalizeUpstreamError(upErr), c.Query("error_description"), req.OrigState)
		return
	}

	code := c.Query("code")
	if code == "" {
		h.redirectError(c, req.RedirectURI, apierror.OAuthServerError, "上游未返回授权码", req.OrigState)
		return
	}

	subject, err := h.upstream.Exchange(c.Request.Context(), code)
	if err != nil {
		h.redirectError(c, req.RedirectURI, apierror.OAuthServerError, "上游换取 token 失败", req.OrigState)
		return
	}

	user, err := h.users.ResolveOrCreateBySubject(c.Request.Context(), subject)
	if err != nil {
		h.redirectError(c, req.RedirectURI, apierror.OAuthServerError, "解析 User 失败", req.OrigState)
		return
	}

	gwCode, err := h.gwcodes.Issue(c.Request.Context(), auth.GWCode{
		CodeChallenge: req.CodeChallenge,
		UserUUID:      user.UUID,
		RedirectURI:   req.RedirectURI,
	})
	if err != nil {
		h.redirectError(c, req.RedirectURI, apierror.OAuthServerError, "签发授权码失败", req.OrigState)
		return
	}

	redirectBack(c, req.RedirectURI, url.Values{"code": {gwCode}, "state": {req.OrigState}})
}

// redirectError 以 302 回跳 redirect_uri，携带 RFC 6749 错误参数与原 state。
func (h *OAuthHandler) redirectError(c *gin.Context, redirectURI, code, description, origState string) {
	redirectBack(c, redirectURI, url.Values{
		"error":             {code},
		"error_description": {description},
		"state":             {origState},
	})
}

// normalizeUpstreamError 归一上游错误码：用户取消（access_denied）原样透传，其余归 server_error。
func normalizeUpstreamError(upstreamErr string) string {
	if upstreamErr == apierror.OAuthAccessDenied {
		return apierror.OAuthAccessDenied
	}
	return apierror.OAuthServerError
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
