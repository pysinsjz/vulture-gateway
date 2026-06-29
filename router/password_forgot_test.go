package router_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// 登出态「忘记密码」路径（#41 / ADR-0015）的 router 级 HTTP 缝测试：登录页入口 → 无 t 的
// 验证码模式页 → 标识 + pwreset 验证码证明身份 → 按 secret 空/非空 set/reset。复用 #40 的
// pwreset 发码/验码与限流（router/password_test.go 的 helper）。

var sidRe = regexp.MustCompile(`name="sid" value="([^"]*)"`)

// extractSID 从验证码模式页提取一次性页面会话 id（sid）隐藏域。
func extractSID(t *testing.T, body string) string {
	t.Helper()
	m := sidRe.FindStringSubmatch(body)
	if len(m) != 2 || m[1] == "" {
		t.Fatalf("未能从页面提取 sid: %s", body)
	}
	return m[1]
}

// forgotPage GET 无 t 的验证码模式页，返回页面会话 sid 与 csrf。
func forgotPage(t *testing.T, e *gin.Engine) (sid, csrf string) {
	t.Helper()
	rec := do(t, e, http.MethodGet, "/oauth/password", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("验证码模式页期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	return extractSID(t, body), extractCSRF(t, body)
}

// ---- 端到端回路：登出态重置 → 账号级生效 → 新密码登录成功、旧密码失败 ----

func TestForgotPassword_ResetRoundTrip(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_f", Type: model.IdentityTypeEmail, Identifier: "f@x.com"})
	idRepo.seed(&model.Identity{UUID: "idn_p", UserUUID: "usr_f", Type: model.IdentityTypePhone, Identifier: "13700000000"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	const oldPassword = "oldpass123"
	const newPassword = "newpass456"
	// 经 #39 绑定路径设初始密码，使账号进入「已设密码」态（登出态重置目标）。
	setInitialPwd(t, e, pub, "usr_f", "dev_f", oldPassword)

	// 登出态：进验证码模式页 → 输标识发码（页面 CSRF + 标识授权）。
	sid, csrf := forgotPage(t, e)
	scRec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"f@x.com"},
	})
	if scRec.Code != http.StatusOK {
		t.Fatalf("登出态发码期望 200, 实际 %d: %s", scRec.Code, scRec.Body.String())
	}
	code := pwresetCode(t, mr, "f@x.com")

	// 标识 + 正确码 + 新密码 → 重置成功，账号级写入。
	setRec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"f@x.com"},
		"code": {code}, "encrypted_password": {encryptRSA(t, pub, newPassword)},
	})
	if setRec.Code != http.StatusOK || !strings.Contains(setRec.Body.String(), "成功") {
		t.Fatalf("登出态重置期望成功页 200, 实际 %d: %s", setRec.Code, setRec.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "f@x.com") != idRepo.secretOf(model.IdentityTypePhone, "13700000000") {
		t.Error("账号级重置：email 与 phone 应写入同一新 hash")
	}

	// 端到端回路：新密码登录成功。
	lk := authorizeAndGetLinkedState(t, e)
	loginCSRF := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk), "", nil).Body.String())
	okLogin := doForm(t, e, http.MethodPost, "/oauth/login", "", url.Values{
		"lk": {lk}, "method": {"password"}, "identifier": {"f@x.com"},
		"credential": {encryptRSA(t, pub, newPassword)}, "csrf": {loginCSRF},
	})
	if okLogin.Code != http.StatusFound {
		t.Fatalf("新密码登录期望 302, 实际 %d: %s", okLogin.Code, okLogin.Body.String())
	}

	// 旧密码登录失败。
	lk2 := authorizeAndGetLinkedState(t, e)
	loginCSRF2 := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk2), "", nil).Body.String())
	badLogin := doForm(t, e, http.MethodPost, "/oauth/login", "", url.Values{
		"lk": {lk2}, "method": {"password"}, "identifier": {"f@x.com"},
		"credential": {encryptRSA(t, pub, oldPassword)}, "csrf": {loginCSRF2},
	})
	if badLogin.Code == http.StatusFound {
		t.Fatal("旧密码登录应失败（非 302）")
	}
}

// ---- 验证码模式页渲染 ----

func TestForgotPage_CodeMode_Renders(t *testing.T) {
	e, _, _ := newPasswordEngine(t, newMemIdentityRepo())

	rec := do(t, e, http.MethodGet, "/oauth/password", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("无 t 期望 200 验证码模式页, 实际 %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"重置登录密码", `name="identifier"`, "验证码", "发送验证码"} {
		if !strings.Contains(body, want) {
			t.Errorf("验证码模式页应含 %q, 实际: %s", want, body)
		}
	}
	// 标识应可编辑（非 readonly，与绑定模式页的只读预填相对）。
	if strings.Contains(body, `id="identifier" value="" autocomplete="username" readonly`) {
		t.Error("验证码模式页的标识输入不应 readonly")
	}
	extractSID(t, body)  // 应含 sid 隐藏域
	extractCSRF(t, body) // 应含 csrf 隐藏域
}

// ---- 登出态首设：secret 空 → set；新密码登录成功 ----

func TestForgotPassword_SetFirstPassword_RoundTrip(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_s", Type: model.IdentityTypeEmail, Identifier: "s@x.com"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	const newPassword = "setpass789"
	sid, csrf := forgotPage(t, e)
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"s@x.com"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("发码期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	code := pwresetCode(t, mr, "s@x.com")

	setRec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"s@x.com"},
		"code": {code}, "encrypted_password": {encryptRSA(t, pub, newPassword)},
	})
	if setRec.Code != http.StatusOK || !strings.Contains(setRec.Body.String(), "设置成功") {
		t.Fatalf("登出态首设期望「设置成功」, 实际 %d: %s", setRec.Code, setRec.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "s@x.com") == "" {
		t.Fatal("首设后 secret 应被写入")
	}

	// 端到端：新密码登录成功。
	lk := authorizeAndGetLinkedState(t, e)
	loginCSRF := extractCSRF(t, do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk), "", nil).Body.String())
	if rec := doForm(t, e, http.MethodPost, "/oauth/login", "", url.Values{
		"lk": {lk}, "method": {"password"}, "identifier": {"s@x.com"},
		"credential": {encryptRSA(t, pub, newPassword)}, "csrf": {loginCSRF},
	}); rec.Code != http.StatusFound {
		t.Fatalf("首设后新密码登录期望 302, 实际 %d", rec.Code)
	}
}

// ---- 防账号枚举：不存在 / 错码 不泄露存在性 ----

func TestForgotPassword_AntiEnumeration(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_a", Type: model.IdentityTypeEmail, Identifier: "exists@x.com"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	sid, csrf := forgotPage(t, e)

	// 发码：存在与不存在的标识返回同形（均 200），不泄露存在性。
	existRec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"exists@x.com"},
	})
	missRec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"ghost@x.com"},
	})
	if existRec.Code != http.StatusOK || missRec.Code != http.StatusOK {
		t.Fatalf("发码应对存在/不存在同形 200: exists=%d ghost=%d", existRec.Code, missRec.Code)
	}

	// 错码提交：存在与不存在标识应得相同通用提示「验证码错误或已失效」，均不暴露存在性、不到达「无法设置密码」。
	_ = pwresetCode(t, mr, "exists@x.com") // 确有真实码（用错码提交）
	for _, id := range []string{"exists@x.com", "ghost@x.com"} {
		rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
			"sid": {sid}, "csrf": {csrf}, "identifier": {id},
			"code": {"000000"}, "encrypted_password": {encryptRSA(t, pub, "newpass456")},
		})
		body := rec.Body.String()
		if !strings.Contains(body, "验证码错误或已失效") {
			t.Errorf("标识 %q 错码应回通用「验证码错误或已失效」, 实际: %s", id, body)
		}
		if strings.Contains(body, "无法设置密码") || strings.Contains(body, "成功") {
			t.Errorf("标识 %q 错码不应暴露存在性: %s", id, body)
		}
		// 每次错码消费 csrf，需重取页面 sid/csrf。
		sid, csrf = forgotPage(t, e)
	}

	if idRepo.secretOf(model.IdentityTypeEmail, "exists@x.com") != "" {
		t.Error("错码全程 secret 不应被写入")
	}
}

// ---- oauth-only / 无本地标识：持有效码者越过码闸后得友好拒绝 ----

func TestForgotPassword_OAuthOnly_Friendly(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_o", UserUUID: "usr_o", Type: model.IdentityTypeOAuth, Identifier: "gh|7", Provider: "github"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	const dest = "ghuser@x.com" // oauth 用户没有此本地标识
	sid, csrf := forgotPage(t, e)
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {dest},
	}); rec.Code != http.StatusOK {
		t.Fatalf("发码期望 200, 实际 %d", rec.Code)
	}
	code := pwresetCode(t, mr, dest)

	// 持有效码（证明拥有该收件箱）→ 越过码闸 → 无本地标识 → 友好拒绝。
	rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {dest},
		"code": {code}, "encrypted_password": {encryptRSA(t, pub, "newpass456")},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无本地标识期望 400 友好拒绝, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "无法设置密码") {
		t.Errorf("应友好告知无法设置, 实际: %s", rec.Body.String())
	}
}

// ---- 缺码：被拒、不计失败、不改 secret ----

func TestForgotPassword_MissingCode_Rejected(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_mc", Type: model.IdentityTypeEmail, Identifier: "mc@x.com"})
	e, _, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	sid, csrf := forgotPage(t, e)
	rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"mc@x.com"},
		"encrypted_password": {encryptRSA(t, pub, "newpass456")}, // 无 code
	})
	body := rec.Body.String()
	if strings.Contains(body, "成功") {
		t.Fatalf("缺码不应成功: %s", body)
	}
	if !strings.Contains(body, "验证码") {
		t.Errorf("缺码应提示需验证码, 实际: %s", body)
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "mc@x.com") != "" {
		t.Error("缺码被拒后不应写入 secret")
	}
}

// ---- 命中本地标识带 provider（联合身份）→ 不视为可设密码的本地标识 ----

// 即便某 email/phone 标识能被验证码证明持有，只要它带 provider（第三方来源，非本地登录身份），
// 也不应据此设/改账号密码——与「账号级密码只写 provider 为空的本地身份」（ADR-0015）一致。
func TestForgotPassword_ProviderBoundIdentity_Friendly(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_fed", UserUUID: "usr_fed", Type: model.IdentityTypeEmail, Identifier: "fed@x.com", Provider: "github"})
	e, mr, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	sid, csrf := forgotPage(t, e)
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"fed@x.com"},
	}); rec.Code != http.StatusOK {
		t.Fatalf("发码期望 200, 实际 %d", rec.Code)
	}
	code := pwresetCode(t, mr, "fed@x.com")

	// 持有效码越过码闸 → 标识带 provider → 友好拒绝、不写 secret。
	rec := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"sid": {sid}, "csrf": {csrf}, "identifier": {"fed@x.com"},
		"code": {code}, "encrypted_password": {encryptRSA(t, pub, "newpass456")},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "无法设置密码") {
		t.Fatalf("带 provider 标识应友好拒绝 400, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "fed@x.com") != "" {
		t.Error("带 provider 标识不应被写入 secret")
	}
}

// ---- 页面 CSRF：发码与提交均须有效 csrf ----

func TestForgotPassword_CSRF_Required(t *testing.T) {
	idRepo := newMemIdentityRepo()
	idRepo.seed(&model.Identity{UUID: "idn_e", UserUUID: "usr_x", Type: model.IdentityTypeEmail, Identifier: "x@x.com"})
	e, _, priv := newPasswordEngine(t, idRepo)
	pub := &priv.PublicKey

	sid, _ := forgotPage(t, e)

	// 发码：坏 csrf → 400。
	if rec := doForm(t, e, http.MethodPost, "/oauth/password/send-code", "", url.Values{
		"sid": {sid}, "csrf": {"bogus"}, "identifier": {"x@x.com"},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("坏 csrf 发码期望 400, 实际 %d", rec.Code)
	}

	// 提交：坏 csrf → 回渲「会话已失效」，secret 不变。
	bad := doForm(t, e, http.MethodPost, "/oauth/password", "", url.Values{
		"sid": {sid}, "csrf": {"bogus"}, "identifier": {"x@x.com"},
		"code": {"123456"}, "encrypted_password": {encryptRSA(t, pub, "newpass456")},
	})
	if strings.Contains(bad.Body.String(), "成功") {
		t.Fatalf("坏 csrf 提交不应成功: %s", bad.Body.String())
	}
	if !strings.Contains(bad.Body.String(), "会话已失效") {
		t.Errorf("坏 csrf 提交应提示会话已失效, 实际: %s", bad.Body.String())
	}
	if idRepo.secretOf(model.IdentityTypeEmail, "x@x.com") != "" {
		t.Error("坏 csrf 全程 secret 不应被写入")
	}
}

// ---- 登录页入口：含「忘记密码?」链接指向 /oauth/password ----

func TestLoginPage_HasForgotPasswordLink(t *testing.T) {
	e, _, _ := newPasswordEngine(t, newMemIdentityRepo())
	lk := authorizeAndGetLinkedState(t, e)
	body := do(t, e, http.MethodGet, "/oauth/login?lk="+url.QueryEscape(lk), "", nil).Body.String()
	if !strings.Contains(body, `href="/oauth/password"`) {
		t.Errorf("登录页应含指向 /oauth/password 的链接, 实际: %s", body)
	}
	if !strings.Contains(body, "忘记密码") {
		t.Errorf("登录页应含「忘记密码」文案, 实际: %s", body)
	}
}
