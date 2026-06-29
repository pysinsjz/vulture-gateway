package handler

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// PasswordHandler 承接「登录态首次设密码」（ADR-0015 / #39，绑定路径、免 OTP）：
//   - POST /api/v1/auth/password-link（唯一 Bearer 端点，桌面端调）：铸一次性 Password Link，返回托管页 URL。
//   - GET  /oauth/password?t=（公开页面）：凭 t 渲染绑定模式页（标识预填、内嵌 RSA 公钥 + CSRF）。
//   - POST /oauth/password（公开页面）：浏览器内 RSA 加密的新密码提交，解密+校验+账号级写入。
//
// 关键约束：托管页跑在系统浏览器、无桌面 Bearer，故页面作用域端点不走 JWTAuth，靠 t + 一次性 CSRF 授权。
type PasswordHandler struct {
	pwService   *service.PasswordService
	links       *auth.PasswordLinkStore
	csrf        *auth.CSRFStore
	rsa         *auth.RSADecryptor
	gatewayBase string
	formTmpl    *template.Template
	resultTmpl  *template.Template
}

// NewPasswordHandler 构造设密码 handler。gatewayBase 为网关外部基址（拼托管页 URL）。
func NewPasswordHandler(
	pwService *service.PasswordService,
	links *auth.PasswordLinkStore,
	csrf *auth.CSRFStore,
	rsa *auth.RSADecryptor,
	gatewayBase string,
) *PasswordHandler {
	return &PasswordHandler{
		pwService:   pwService,
		links:       links,
		csrf:        csrf,
		rsa:         rsa,
		gatewayBase: gatewayBase,
		formTmpl:    template.Must(template.New("pwForm").Parse(passwordPageTmpl)),
		resultTmpl:  template.Must(template.New("pwResult").Parse(passwordResultTmpl)),
	}
}

type passwordLinkResponse struct {
	URL string `json:"url"`
}

type passwordFormData struct {
	Token        string
	CSRFToken    string
	PublicKeyB64 string
	Identifier   string
	Error        string
}

type passwordResultData struct {
	Title   string
	Message string
}

// PasswordLink 铸取一次性 Password Link，返回内嵌 t 的托管页 URL。
//
//	POST /api/v1/auth/password-link  (Bearer)
func (h *PasswordHandler) PasswordLink(c *gin.Context) {
	userUUID := c.GetString(middleware.CtxKeySub)
	if userUUID == "" {
		// JWTAuth 已保证有 sub；防御性兜底。
		renderErrorPage(c, "登录状态无效，请重新登录。")
		return
	}
	token, err := h.links.Issue(c.Request.Context(), auth.PasswordLink{UserUUID: userUUID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "铸取设置密码链接失败"})
		return
	}
	c.JSON(http.StatusOK, passwordLinkResponse{URL: h.gatewayBase + "/oauth/password?t=" + token})
}

// PasswordPage 渲染绑定模式设密码页。
//
//	GET /oauth/password?t=<token>  (公开)
func (h *PasswordHandler) PasswordPage(c *gin.Context) {
	token := c.Query("t")
	if token == "" {
		// 本切片（#39）只做绑定路径；登出态验证码模式留给 #41。无 t 引导回桌面端发起。
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "请从桌面端「设置」中发起设置密码。")
		return
	}
	link, found, err := h.links.Peek(c.Request.Context(), token)
	if err != nil {
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "页面初始化失败，请稍后重试。")
		return
	}
	if !found {
		h.renderResult(c, http.StatusBadRequest, "链接已失效", "设置密码链接无效或已过期，请重新发起。")
		return
	}
	h.renderForm(c, token, link.UserUUID, "")
}

// SubmitPassword 处理设密码提交：校验 t/CSRF → 解密 → 校验策略 → 账号级写入 → 成功消费 t。
//
//	POST /oauth/password  (公开)
func (h *PasswordHandler) SubmitPassword(c *gin.Context) {
	token := c.PostForm("t")
	csrfToken := c.PostForm("csrf")
	encrypted := c.PostForm("encrypted_password")

	// 先 Peek（不消费）确认链接有效，定位账号。成功写入后才 Take 消费（单次有效）。
	link, found, err := h.links.Peek(c.Request.Context(), token)
	if err != nil {
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "页面初始化失败，请稍后重试。")
		return
	}
	if !found {
		h.renderResult(c, http.StatusBadRequest, "链接已失效", "设置密码链接无效或已过期，请重新发起。")
		return
	}

	// 一次性 CSRF：消费后无论成败都需重新签发（renderForm 会签发新的）。
	if ok, err := h.csrf.Consume(c.Request.Context(), token, csrfToken); err != nil || !ok {
		h.renderForm(c, token, link.UserUUID, "会话已失效，请重试。")
		return
	}

	err = h.pwService.SetInitialPassword(c.Request.Context(), link.UserUUID, encrypted)
	switch {
	case err == nil:
		// 设置成功：消费链接（单次有效、防重放），渲染成功页。
		_, _, _ = h.links.Take(c.Request.Context(), token)
		h.renderResult(c, http.StatusOK, "设置成功", "密码已设置，现在可以用新密码登录了。")
	case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong):
		h.renderForm(c, token, link.UserUUID, "密码须为 8–64 个字符。")
	case errors.Is(err, auth.ErrPasswordMissingKind):
		h.renderForm(c, token, link.UserUUID, "密码须同时包含字母与数字。")
	case errors.Is(err, service.ErrInvalidCiphertext):
		h.renderForm(c, token, link.UserUUID, "密码提交无效，请重试。")
	case errors.Is(err, service.ErrPasswordAlreadySet):
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "账号已设置密码；如需修改，请使用验证码方式（暂未开放）。")
	case errors.Is(err, service.ErrNoLocalIdentity):
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "当前账号没有可设置密码的邮箱/手机标识。")
	default:
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "设置密码出错，请稍后重试。")
	}
}

// renderForm 校验绑定上下文 → 签发新 CSRF → 渲染设密码表单（可带错误提示）。
// 已设密码 / 无本地标识 / 系统错误时转渲终态结果页。
func (h *PasswordHandler) renderForm(c *gin.Context, token, userUUID, errMsg string) {
	binding, err := h.pwService.Binding(c.Request.Context(), userUUID)
	switch {
	case errors.Is(err, service.ErrNoLocalIdentity):
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "当前账号没有可设置密码的邮箱/手机标识。")
		return
	case err != nil:
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "页面初始化失败，请稍后重试。")
		return
	}
	if !binding.CanSet {
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "账号已设置密码；如需修改，请使用验证码方式（暂未开放）。")
		return
	}

	csrfToken, err := h.csrf.Issue(c.Request.Context(), token)
	if err != nil {
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "页面初始化失败，请稍后重试。")
		return
	}
	pubB64, err := spkiBase64(h.rsa.PublicKeyPEM())
	if err != nil {
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "页面初始化失败，请稍后重试。")
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = h.formTmpl.Execute(c.Writer, passwordFormData{
		Token:        token,
		CSRFToken:    csrfToken,
		PublicKeyB64: pubB64,
		Identifier:   binding.Identifier,
		Error:        errMsg,
	})
}

// renderResult 渲染终态结果页（成功/失败）。
func (h *PasswordHandler) renderResult(c *gin.Context, status int, title, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = h.resultTmpl.Execute(c.Writer, passwordResultData{Title: title, Message: message})
}
