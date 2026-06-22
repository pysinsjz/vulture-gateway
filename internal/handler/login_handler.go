package handler

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/auth/signin"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// LoginHandler 承接网关自建登录页（ADR-0013）：渲染登录页、处理凭据提交与验证码下发，
// 成功后续接既有 GW_CODE 签发与回跳桌面端（下游零改动）。
type LoginHandler struct {
	registry *signin.Registry
	otpSvc   *service.OTPService
	authz    *auth.AuthzStore
	gwcodes  *auth.GWCodeStore
	users    dao.UserRepository
	rsa      *auth.RSADecryptor
	csrf     *auth.CSRFStore
	tmpl     *template.Template
}

// NewLoginHandler 构造登录页 handler。
func NewLoginHandler(
	registry *signin.Registry,
	otpSvc *service.OTPService,
	authz *auth.AuthzStore,
	gwcodes *auth.GWCodeStore,
	users dao.UserRepository,
	rsa *auth.RSADecryptor,
	csrf *auth.CSRFStore,
) *LoginHandler {
	return &LoginHandler{
		registry: registry,
		otpSvc:   otpSvc,
		authz:    authz,
		gwcodes:  gwcodes,
		users:    users,
		rsa:      rsa,
		csrf:     csrf,
		tmpl:     template.Must(template.New("login").Parse(loginPageTmpl)),
	}
}

type loginPageData struct {
	LinkedState  string
	CSRFToken    string
	PublicKeyB64 string // SPKI 公钥 DER 的 base64，供前端 SubtleCrypto 导入
	Methods      []loginMethodView
	Error        string
}

type loginMethodView struct {
	Name     string
	Label    string
	IsCode   bool // 验证码方式（渲染发码按钮）
	Selected bool
}

// LoginPage 渲染登录页。
//
//	GET /oauth/login?lk=<linkedState>  (公开)
func (h *LoginHandler) LoginPage(c *gin.Context) {
	linkedState := c.Query("lk")
	if _, found, err := h.authz.Peek(c.Request.Context(), linkedState); err != nil || !found {
		renderErrorPage(c, "登录状态无效或已过期，请重新发起登录。")
		return
	}
	h.render(c, linkedState, "")
}

// render 签发新的 CSRF token 并渲染登录页（可带错误提示）。
func (h *LoginHandler) render(c *gin.Context, linkedState, errMsg string) {
	token, err := h.csrf.Issue(c.Request.Context(), linkedState)
	if err != nil {
		renderErrorPage(c, "登录页初始化失败，请稍后重试。")
		return
	}

	pubB64, err := spkiBase64(h.rsa.PublicKeyPEM())
	if err != nil {
		renderErrorPage(c, "登录页初始化失败，请稍后重试。")
		return
	}

	data := loginPageData{
		LinkedState:  linkedState,
		CSRFToken:    token,
		PublicKeyB64: pubB64,
		Methods:      h.methodViews(),
		Error:        errMsg,
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = h.tmpl.Execute(c.Writer, data)
}

func (h *LoginHandler) methodViews() []loginMethodView {
	methods := h.registry.List()
	views := make([]loginMethodView, 0, len(methods))
	for i, m := range methods {
		views = append(views, loginMethodView{
			Name:     m.Name(),
			Label:    methodLabel(m.Name()),
			IsCode:   m.Name() != "password",
			Selected: i == 0,
		})
	}
	return views
}

// Login 处理登录提交：校验 CSRF → 按方式 Verify → 解析 User → 签发 GW_CODE → 回跳桌面端。
//
//	POST /oauth/login  (公开)
func (h *LoginHandler) Login(c *gin.Context) {
	linkedState := c.PostForm("lk")
	method := c.PostForm("method")
	identifier := c.PostForm("identifier")
	credential := c.PostForm("credential")
	csrfToken := c.PostForm("csrf")

	// 先确认会话有效（Peek 不消费，留待成功后 Take）。
	if _, found, err := h.authz.Peek(c.Request.Context(), linkedState); err != nil || !found {
		renderErrorPage(c, "登录状态无效或已过期，请重新发起登录。")
		return
	}

	// 一次性 CSRF：消费后无论成败都需重新签发（render 会签发新的）。
	if ok, err := h.csrf.Consume(c.Request.Context(), linkedState, csrfToken); err != nil || !ok {
		h.render(c, linkedState, "会话已失效，请重试。")
		return
	}

	m, ok := h.registry.Get(method)
	if !ok {
		h.render(c, linkedState, "不支持的登录方式。")
		return
	}

	subject, err := m.Verify(c.Request.Context(), signin.VerifyInput{
		Identifier: identifier,
		Credential: credential,
		IP:         c.ClientIP(),
	})
	if err != nil {
		if msg, isBiz := loginBusinessMessage(err); isBiz {
			h.render(c, linkedState, msg)
			return
		}
		renderErrorPage(c, "登录处理出错，请稍后重试。")
		return
	}

	user, err := h.users.ResolveOrCreateBySubject(c.Request.Context(), subject)
	if err != nil {
		renderErrorPage(c, "登录处理出错，请稍后重试。")
		return
	}

	// 至此校验通过，消费 authz 请求并签发 GW_CODE（与原 Callback 同构，下游零改动）。
	req, found, err := h.authz.Take(c.Request.Context(), linkedState)
	if err != nil || !found {
		renderErrorPage(c, "登录状态无效或已过期，请重新发起登录。")
		return
	}

	gwCode, err := h.gwcodes.Issue(c.Request.Context(), auth.GWCode{
		CodeChallenge: req.CodeChallenge,
		UserUUID:      user.UUID,
		RedirectURI:   req.RedirectURI,
	})
	if err != nil {
		renderErrorPage(c, "登录处理出错，请稍后重试。")
		return
	}

	redirectBack(c, req.RedirectURI, url.Values{"code": {gwCode}, "state": {req.OrigState}})
}

type sendCodeResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// SendCode 处理验证码下发请求（登录页 AJAX）。
//
//	POST /oauth/send-code  (公开)
func (h *LoginHandler) SendCode(c *gin.Context) {
	linkedState := c.PostForm("lk")
	method := c.PostForm("method")
	identifier := c.PostForm("identifier")

	if _, found, err := h.authz.Peek(c.Request.Context(), linkedState); err != nil || !found {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "登录状态无效或已过期"})
		return
	}

	channel, ok := channelForMethod(method)
	if !ok {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "该方式不支持验证码"})
		return
	}
	if identifier == "" {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "请输入登录标识"})
		return
	}

	err := h.otpSvc.SendCode(c.Request.Context(), channel, identifier, c.ClientIP())
	switch {
	case err == nil:
		c.JSON(http.StatusOK, sendCodeResponse{OK: true})
	case errors.Is(err, service.ErrResendTooSoon):
		c.JSON(http.StatusTooManyRequests, sendCodeResponse{Error: "发送过于频繁，请稍后再试"})
	case errors.Is(err, service.ErrSendRateLimited):
		c.JSON(http.StatusTooManyRequests, sendCodeResponse{Error: "发送次数过多，请稍后再试"})
	default:
		c.JSON(http.StatusInternalServerError, sendCodeResponse{Error: "发送失败，请稍后重试"})
	}
}

// ---- 辅助 ----

// channelForMethod 把登录方式映射到验证码渠道。
func channelForMethod(method string) (string, bool) {
	switch method {
	case "email_code":
		return model.ProviderCategoryEmail, true
	case "sms_code":
		return model.ProviderCategorySMS, true
	default:
		return "", false
	}
}

func methodLabel(name string) string {
	switch name {
	case "password":
		return "密码登录"
	case "email_code":
		return "邮箱验证码"
	case "sms_code":
		return "手机验证码"
	default:
		return name
	}
}

// loginBusinessMessage 把 signin 业务错误映射为用户可见提示；isBiz=false 表示系统错误。
func loginBusinessMessage(err error) (string, bool) {
	switch {
	case errors.Is(err, signin.ErrInvalidCredentials):
		return "标识或密码错误。", true
	case errors.Is(err, signin.ErrInvalidCode):
		return "验证码错误或已失效。", true
	case errors.Is(err, signin.ErrAccountLocked):
		return "尝试过于频繁，请稍后再试。", true
	default:
		return "", false
	}
}

// spkiBase64 从 SPKI 公钥 PEM 提取 DER 的 base64 编码（供前端 SubtleCrypto importKey('spki')）。
func spkiBase64(pubPEM string) (string, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return "", errors.New("公钥 PEM 解析失败")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}
