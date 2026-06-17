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
	clientID string // 期望的桌面端 client_id（vulture-desktop）
}

// NewOAuthHandler 构造 handler。
func NewOAuthHandler(upstream auth.UpstreamIDP, authz *auth.AuthzStore, gwcodes *auth.GWCodeStore, users dao.UserRepository, clientID string) *OAuthHandler {
	return &OAuthHandler{upstream: upstream, authz: authz, gwcodes: gwcodes, users: users, clientID: clientID}
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
//
//	GET /oauth/callback/casdoor  (上游回调)
func (h *OAuthHandler) Callback(c *gin.Context) {
	code := c.Query("code")
	linkedState := c.Query("state")
	if code == "" || linkedState == "" {
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "缺失 code 或 state")
		return
	}

	req, found, err := h.authz.Take(c.Request.Context(), linkedState)
	if err != nil {
		apierror.AbortOAuth(c, http.StatusInternalServerError, apierror.OAuthServerError, "读取授权请求失败")
		return
	}
	if !found {
		// state 失效/非法：网关已无 redirect_uri，无法回跳。完整极简错误页见 #15。
		apierror.AbortOAuth(c, http.StatusBadRequest, apierror.OAuthInvalidRequest, "state 无效或已过期")
		return
	}

	// 自此已知 redirect_uri，失败按 RFC 6749 回跳（错误分类在 #15 完善）。
	subject, err := h.upstream.Exchange(c.Request.Context(), code)
	if err != nil {
		redirectBack(c, req.RedirectURI, url.Values{"error": {apierror.OAuthServerError}, "error_description": {"上游换取 token 失败"}, "state": {req.OrigState}})
		return
	}

	user, err := h.users.ResolveOrCreateBySubject(c.Request.Context(), subject)
	if err != nil {
		redirectBack(c, req.RedirectURI, url.Values{"error": {apierror.OAuthServerError}, "error_description": {"解析 User 失败"}, "state": {req.OrigState}})
		return
	}

	gwCode, err := h.gwcodes.Issue(c.Request.Context(), auth.GWCode{
		CodeChallenge: req.CodeChallenge,
		UserUUID:      user.UUID,
		RedirectURI:   req.RedirectURI,
	})
	if err != nil {
		redirectBack(c, req.RedirectURI, url.Values{"error": {apierror.OAuthServerError}, "error_description": {"签发授权码失败"}, "state": {req.OrigState}})
		return
	}

	redirectBack(c, req.RedirectURI, url.Values{"code": {gwCode}, "state": {req.OrigState}})
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
