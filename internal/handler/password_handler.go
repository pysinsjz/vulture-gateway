package handler

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// PasswordHandler 承接「登录态首次设密码」（ADR-0015 / #39，绑定路径、免 OTP）：
//   - POST /api/v1/auth/password-link（唯一 Bearer 端点，桌面端调）：铸一次性 Password Link，返回托管页 URL。
//   - GET  /oauth/password?t=（公开页面）：凭 t 渲染绑定模式页（标识预填、内嵌 RSA 公钥 + CSRF）。
//   - POST /oauth/password（公开页面）：浏览器内 RSA 加密的新密码提交，解密+校验+账号级写入。
//
// 关键约束：托管页跑在系统浏览器、无桌面 Bearer，故页面作用域端点不走 JWTAuth，靠 t + 一次性 CSRF 授权。
type PasswordHandler struct {
	pwService      *service.PasswordService
	otpSvc         *service.OTPService
	links          *auth.PasswordLinkStore
	csrf           *auth.CSRFStore
	rsa            *auth.RSADecryptor
	gatewayBase    string
	allowPlaintext bool // dev/test 旁路：是否允许 plain_password 字段（cfg.Auth.AllowPlaintextPassword）
	formTmpl       *template.Template
	codeTmpl       *template.Template
	resultTmpl     *template.Template
}

// NewPasswordHandler 构造设密码 handler。gatewayBase 为网关外部基址（拼托管页 URL）；
// otpSvc 供改密路径页面作用域发码（POST /oauth/password/send-code，purpose=pwreset）。
// allowPlaintext 是 dev/test 旁路（cfg.Auth.AllowPlaintextPassword）：true 时接受 plain_password
// 字段，handler 用 RSA 公钥就地加密后喂给 service；prod/staging 由 config.validate 顶为 false。
func NewPasswordHandler(
	pwService *service.PasswordService,
	otpSvc *service.OTPService,
	links *auth.PasswordLinkStore,
	csrf *auth.CSRFStore,
	rsa *auth.RSADecryptor,
	gatewayBase string,
	allowPlaintext bool,
) *PasswordHandler {
	return &PasswordHandler{
		pwService:      pwService,
		otpSvc:         otpSvc,
		links:          links,
		csrf:           csrf,
		rsa:            rsa,
		gatewayBase:    gatewayBase,
		allowPlaintext: allowPlaintext,
		formTmpl:       template.Must(template.New("pwForm").Parse(passwordPageTmpl)),
		codeTmpl:       template.Must(template.New("pwCodeForm").Parse(passwordCodePageTmpl)),
		resultTmpl:     template.Must(template.New("pwResult").Parse(passwordResultTmpl)),
	}
}

// resolveEncrypted 是 PasswordHandler 上的薄包装，转发到包级 resolveSubmittedPassword。
func (h *PasswordHandler) resolveEncrypted(encrypted, plain string) (string, string) {
	return resolveSubmittedPassword(h.rsa, h.allowPlaintext, encrypted, plain)
}

type passwordLinkResponse struct {
	URL string `json:"url"`
}

type passwordFormData struct {
	Token        string
	CSRFToken    string
	PublicKeyB64 string
	Identifier   string
	RequireCode  bool // true=改密（验证码模式，渲染发码按钮+验证码输入）；false=首设（免码）
	Error        string
}

// passwordCodeFormData 是登出态忘记密码（验证码模式）页的渲染数据。SID 为页面一次性会话 id，
// CSRF token 绑定其上：授权页面作用域的发码/提交。Identifier 在错误重渲时回填（少让用户重输）。
type passwordCodeFormData struct {
	SID          string
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
		// 无 t → 登出态忘记密码（验证码模式，#41）：自填标识 + pwreset 验证码证明身份。
		h.renderCodeForm(c, "", "")
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

// SendResetCode 页面作用域发码（purpose=pwreset），非 Bearer：
//   - 绑定路径（有 t）：靠 t 定位账号自有标识发码（#40）。
//   - 忘记密码路径（无 t）：靠页面一次性 CSRF（绑定 sid）+ 提交的标识授权，向该标识发码（#41）。
//
//	POST /oauth/password/send-code  (公开)
func (h *PasswordHandler) SendResetCode(c *gin.Context) {
	token := c.PostForm("t")
	if token == "" {
		h.sendForgotCode(c)
		return
	}
	link, found, err := h.links.Peek(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, sendCodeResponse{Error: "发送失败，请稍后重试"})
		return
	}
	if !found {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "链接已失效，请重新发起"})
		return
	}

	dest, channel, err := h.pwService.ResetChannel(c.Request.Context(), link.UserUUID)
	if err != nil {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "当前账号没有可发送验证码的邮箱/手机标识"})
		return
	}

	switch err := h.otpSvc.SendCode(c.Request.Context(), channel, dest, c.ClientIP(), auth.PurposePasswordReset); {
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

// SubmitPassword 处理设/改密提交：校验 t/CSRF → 依 secret 状态分派首设（免码）或改密（验证码）→
// 账号级写入 → 成功消费 t。
//
//	POST /oauth/password  (公开)
func (h *PasswordHandler) SubmitPassword(c *gin.Context) {
	token := c.PostForm("t")
	if token == "" {
		h.submitForgotPassword(c)
		return
	}
	csrfToken := c.PostForm("csrf")
	encrypted, errMsg := h.resolveEncrypted(c.PostForm("encrypted_password"), c.PostForm("plain_password"))
	code := c.PostForm("code")

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

	// 明文旁路被拒（prod/staging 未开 AllowPlaintextPassword）：在 CSRF 已消费后回渲，
	// renderForm 会签发新的 CSRF，避免用户卡死。
	if errMsg != "" {
		h.renderForm(c, token, link.UserUUID, errMsg)
		return
	}

	// 依 secret 状态分派：secret 空→首设（免码）；secret 非空→改密（需 pwreset 验证码）。
	binding, err := h.pwService.Binding(c.Request.Context(), link.UserUUID)
	switch {
	case errors.Is(err, service.ErrNoLocalIdentity):
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "当前账号没有可设置密码的邮箱/手机标识。")
		return
	case err != nil:
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "提交处理出错，请稍后重试。")
		return
	}

	if binding.CanSet {
		err = h.pwService.SetInitialPassword(c.Request.Context(), link.UserUUID, encrypted)
	} else {
		err = h.pwService.ResetPassword(c.Request.Context(), link.UserUUID, encrypted, code, c.ClientIP())
	}

	switch {
	case err == nil:
		// 成功：消费链接（单次有效、防重放），渲染成功页。
		_, _, _ = h.links.Take(c.Request.Context(), token)
		if binding.CanSet {
			h.renderResult(c, http.StatusOK, "设置成功", "密码已设置，现在可以用新密码登录了。")
		} else {
			h.renderResult(c, http.StatusOK, "修改成功", "密码已修改，现在可以用新密码登录了。")
		}
	case errors.Is(err, service.ErrResetLocked):
		h.renderForm(c, token, link.UserUUID, "尝试过于频繁，请稍后再试。")
	case errors.Is(err, service.ErrResetCodeRequired):
		h.renderForm(c, token, link.UserUUID, "请输入邮箱/手机验证码。")
	case errors.Is(err, service.ErrResetCodeInvalid):
		h.renderForm(c, token, link.UserUUID, "验证码错误或已失效，请重试。")
	case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong):
		h.renderForm(c, token, link.UserUUID, "密码须为 8–64 个字符。")
	case errors.Is(err, auth.ErrPasswordMissingKind):
		h.renderForm(c, token, link.UserUUID, "密码须同时包含字母与数字。")
	case errors.Is(err, service.ErrInvalidCiphertext):
		h.renderForm(c, token, link.UserUUID, "密码提交无效，请重试。")
	case errors.Is(err, service.ErrPasswordAlreadySet):
		// 并发：Peek 后被他途设密码。回渲表单（此时已转为改密模式）。
		h.renderForm(c, token, link.UserUUID, "账号状态已变化，请重试。")
	case errors.Is(err, service.ErrNoLocalIdentity):
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "当前账号没有可设置密码的邮箱/手机标识。")
	default:
		h.renderResult(c, http.StatusInternalServerError, "设置密码", "设置密码出错，请稍后重试。")
	}
}

// renderForm 校验绑定上下文 → 签发新 CSRF → 渲染设/改密表单（可带错误提示）。
// secret 空 → 首设模式（免码）；secret 非空 → 改密模式（RequireCode，渲染发码按钮）。
// 无本地标识 / 系统错误时转渲终态结果页。
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
		RequireCode:  !binding.CanSet,
		Error:        errMsg,
	})
}

// sendForgotCode 登出态忘记密码路径发码（无 t）：页面 CSRF（绑定 sid，不消费）+ 标识授权 →
// 向该标识发 pwreset 验证码。防枚举：与登录发码一致，不校验标识是否存在、不泄露存在性。
func (h *PasswordHandler) sendForgotCode(c *gin.Context) {
	sid := c.PostForm("sid")
	csrfToken := c.PostForm("csrf")
	identifier := c.PostForm("identifier")

	// 页面 CSRF 校验但不消费：发码可重试，且其后表单提交仍需该 csrf（一次性消费留到提交）。
	if ok, err := h.csrf.Validate(c.Request.Context(), sid, csrfToken); err != nil || !ok {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "会话已失效，请刷新页面重试"})
		return
	}
	if identifier == "" {
		c.JSON(http.StatusBadRequest, sendCodeResponse{Error: "请输入邮箱或手机号"})
		return
	}

	switch err := h.otpSvc.SendCode(c.Request.Context(), h.pwService.ChannelForIdentifier(identifier), identifier, c.ClientIP(), auth.PurposePasswordReset); {
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

// submitForgotPassword 处理登出态忘记密码提交（无 t）：消费页面 CSRF → 标识 + pwreset 验证码证明身份 →
// 依 secret 空/非空 set/reset → 账号级写入。失败回渲验证码模式页（回填标识、签发新 sid/csrf）。
func (h *PasswordHandler) submitForgotPassword(c *gin.Context) {
	sid := c.PostForm("sid")
	csrfToken := c.PostForm("csrf")
	identifier := c.PostForm("identifier")
	code := c.PostForm("code")
	encrypted, errMsg := h.resolveEncrypted(c.PostForm("encrypted_password"), c.PostForm("plain_password"))

	// 一次性 CSRF：提交即消费（成败都会重渲新页/新 csrf）。
	if ok, err := h.csrf.Consume(c.Request.Context(), sid, csrfToken); err != nil || !ok {
		h.renderCodeForm(c, identifier, "会话已失效，请重试。")
		return
	}

	// 明文旁路被拒（prod/staging 未开 AllowPlaintextPassword）：回渲带提示。
	if errMsg != "" {
		h.renderCodeForm(c, identifier, errMsg)
		return
	}

	firstSet, err := h.pwService.ForgotPassword(c.Request.Context(), identifier, code, encrypted, c.ClientIP())
	switch {
	case err == nil:
		if firstSet {
			h.renderResult(c, http.StatusOK, "设置成功", "密码已设置，现在可以用新密码登录了。")
		} else {
			h.renderResult(c, http.StatusOK, "重置成功", "密码已重置，现在可以用新密码登录了。")
		}
	case errors.Is(err, service.ErrResetLocked):
		h.renderCodeForm(c, identifier, "尝试过于频繁，请稍后再试。")
	case errors.Is(err, service.ErrResetCodeRequired):
		h.renderCodeForm(c, identifier, "请输入邮箱/手机验证码。")
	case errors.Is(err, service.ErrResetCodeInvalid):
		h.renderCodeForm(c, identifier, "验证码错误或已失效，请重试。")
	case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong):
		h.renderCodeForm(c, identifier, "密码须为 8–64 个字符。")
	case errors.Is(err, auth.ErrPasswordMissingKind):
		h.renderCodeForm(c, identifier, "密码须同时包含字母与数字。")
	case errors.Is(err, service.ErrInvalidCiphertext):
		h.renderCodeForm(c, identifier, "密码提交无效，请重试。")
	case errors.Is(err, service.ErrNoLocalIdentity):
		// 仅持有效码者（标识所有者）可达此分支，故友好告知不构成枚举（防枚举见 ForgotPassword）。
		h.renderResult(c, http.StatusBadRequest, "无法设置密码", "该邮箱/手机号无法通过此方式设置密码。")
	default:
		h.renderResult(c, http.StatusInternalServerError, "重置密码", "重置密码出错，请稍后重试。")
	}
}

// renderCodeForm 签发绑定新 sid 的一次性 CSRF → 渲染登出态忘记密码（验证码模式）页（可带错误提示、回填标识）。
func (h *PasswordHandler) renderCodeForm(c *gin.Context, identifier, errMsg string) {
	sid := idgen.New("pwsid")
	csrfToken, err := h.csrf.Issue(c.Request.Context(), sid)
	if err != nil {
		h.renderResult(c, http.StatusInternalServerError, "重置密码", "页面初始化失败，请稍后重试。")
		return
	}
	pubB64, err := spkiBase64(h.rsa.PublicKeyPEM())
	if err != nil {
		h.renderResult(c, http.StatusInternalServerError, "重置密码", "页面初始化失败，请稍后重试。")
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = h.codeTmpl.Execute(c.Writer, passwordCodeFormData{
		SID:          sid,
		CSRFToken:    csrfToken,
		PublicKeyB64: pubB64,
		Identifier:   identifier,
		Error:        errMsg,
	})
}

// renderResult 渲染终态结果页（成功/失败）。
func (h *PasswordHandler) renderResult(c *gin.Context, status int, title, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = h.resultTmpl.Execute(c.Writer, passwordResultData{Title: title, Message: message})
}
