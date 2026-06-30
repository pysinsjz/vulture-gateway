// Package router 负责路由注册与引擎装配。
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/handler"
)

// NewRouter 装配 Gin 引擎并注册路由。
//
// 公开：GET /healthz（存活探针）。
// 管理 API 组 /api/v1（挂 JWTAuth）：受保护 /whoami；公开例外 /bootstrap、/app/latest。
// 脚手架组 /__dev（仅 cfg.Scaffold.Enabled 时挂载）：内部签发 / bump。
func NewRouter(
	cfg *config.Configuration,
	probe *handler.ProbeHandler,
	scaffold *handler.ScaffoldHandler,
	oauth *handler.OAuthHandler,
	login *handler.LoginHandler,
	password *handler.PasswordHandler,
	device *handler.DeviceHandler,
	plugin *handler.PluginHandler,
	skill *handler.SkillHandler,
	telemetry *handler.TelemetryHandler,
	llm *handler.LLMHandler,
	distribution *handler.DistributionHandler,
	bootstrap *handler.BootstrapHandler,
	jwtAuth gin.HandlerFunc,
	jwtAuthLLM gin.HandlerFunc,
) *gin.Engine {
	gin.SetMode(ginMode(cfg.Server.Mode))

	r := gin.New()
	// scoped plugin 包名（如 @vulture/notion-sync）含 `/`，客户端须 URL 编码（%2F）。
	// UseRawPath 让 gin 按转义路径路由，使编码后的名字落在单个 :name 段；
	// UnescapePathValues（默认 true）再把 c.Param 还原为解码值。
	r.UseRawPath = true
	r.UnescapePathValues = true
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// OAuth 端点（公开，不经 JWTAuth）。A1 上半：authorize 暂存后跳网关登录页；token 换码（ADR-0013）。
	// 登录页 GET/POST /oauth/login 由 LoginHandler 承接（Phase 1 阶段五接入）。
	oauthGroup := r.Group("/oauth")
	{
		oauthGroup.GET("/authorize", oauth.Authorize)
		oauthGroup.POST("/token", oauth.Token)
		// 自建登录页（ADR-0013）：渲染、提交、验证码下发。
		oauthGroup.GET("/login", login.LoginPage)
		oauthGroup.POST("/login", login.Login)
		oauthGroup.POST("/send-code", login.SendCode)
		// 网关托管设/改密页（ADR-0015 / #39、#40）：渲染 + 提交 + 改密发码（页面作用域，靠 t + CSRF，不走 JWTAuth）。
		oauthGroup.GET("/password", password.PasswordPage)
		oauthGroup.POST("/password", password.SubmitPassword)
		oauthGroup.POST("/password/send-code", password.SendResetCode) // 改密 pwreset 发码，靠 t 授权
	}

	v1 := r.Group("/api/v1")
	v1.Use(jwtAuth)
	{
		v1.GET("/whoami", probe.Whoami)
		// 公开例外：JWTAuth 放行（见 middleware.DefaultPublicPaths）。
		v1.GET("/bootstrap", bootstrap.Bootstrap)     // 启动引导聚合（公开例外，#28）
		v1.GET("/app/latest", distribution.AppLatest) // 宿主 App 自更新（公开例外，#27）
		// logout 自带鉴权（公开例外）；devices 需 Bearer。
		v1.POST("/auth/logout", device.Logout)
		// 设密码链接（ADR-0015 / #39）：唯一 Bearer 端点，桌面端铸取托管页一次性 Password Link。
		v1.POST("/auth/password-link", password.PasswordLink)
		v1.GET("/devices", device.ListDevices)
		v1.DELETE("/devices/:device_id", device.DeleteDevice)
		// skill 族：鉴权后转发内网 ClawHub skills/skillVersions（#20）。
		v1.GET("/skills", skill.ListSkills)
		v1.GET("/skills/categories", skill.SkillCategories) // 浏览分类+计数（§3.1b，网关派生）；须先于 :slug 通配声明
		v1.GET("/skills/:slug", skill.GetSkill)
		v1.GET("/skills/:slug/versions", skill.ListSkillVersions)
		v1.GET("/skills/:slug/versions/:version", skill.GetSkillVersion)
		v1.GET("/skills/:slug/resolve", skill.ResolveSkill)
		v1.GET("/skills/:slug/download", skill.DownloadSkill)          // 302 跳 R2（#21）
		v1.POST("/skills/-/security-verdicts", skill.SecurityVerdicts) // 批量安全裁决（#22）
		// plugin 族：鉴权后转发内网 ClawHub packages/packageReleases（#19 list 曳光弹 + #20 铺满）。
		v1.GET("/plugins", plugin.ListPlugins)
		v1.GET("/plugins/categories", plugin.PluginCategories) // 浏览分类+计数（§3.1b，网关派生）；须先于 :name 通配声明
		v1.GET("/plugins/:name", plugin.GetPlugin)
		v1.GET("/plugins/:name/versions", plugin.ListPluginVersions) // 版本历史；须先于 :version 通配声明
		v1.GET("/plugins/:name/versions/:version", plugin.GetPluginVersion)
		v1.GET("/plugins/:name/versions/:version/security", plugin.PluginSecurity)                  // 单查安装阻断（#22）
		v1.GET("/plugins/:name/download", plugin.DownloadPlugin)                                    // legacy-zip 302（#21）
		v1.GET("/plugins/:name/versions/:version/artifact/download", plugin.DownloadPluginArtifact) // npm-pack 302（#21）
		// 安装遥测（#22）：best-effort 转发内网 ClawHub 对账。
		v1.POST("/telemetry/install", telemetry.ReportInstall)
	}

	// LLM 代理族（/v1/*，OpenAI 兼容，#23 起）：挂 JWTAuthLLM（失败返 OpenAI 错误体，吊销 403）。
	llmGroup := r.Group("/v1")
	llmGroup.Use(jwtAuthLLM)
	{
		llmGroup.GET("/models", llm.ListModels)
		llmGroup.POST("/chat/completions", llm.ChatCompletions)    // 流式推理 SSE + include_usage 注入 + 双超时（#24）
		llmGroup.POST("/images/generations", llm.ImageGenerations) // 图片生成代理（同步 JSON，门禁同 chat；图片计价 park 待接入）
		llmGroup.POST("/images/edits", llm.ImageEdits)             // 图片编辑代理（multipart/form-data 透传 Content-Type；计价同 park）
	}

	// 千问 DashScope 透传族：路径与 litellm 1:1 镜像，桌面端只需把 host 换成网关。
	// 同样挂 JWTAuthLLM，确保 401/403 沿用 OpenAI 错误体口径。门禁与计量复用 ImageGenerations 同款（park）。
	qianwenGroup := r.Group("/qianwenai/api/v1/services/aigc/multimodal-generation")
	qianwenGroup.Use(jwtAuthLLM)
	{
		qianwenGroup.POST("/generation", llm.QianwenMultimodalGeneration)
	}

	if cfg.Scaffold.Enabled {
		dev := r.Group("/__dev")
		{
			dev.POST("/token", scaffold.IssueToken)
			dev.POST("/bump", scaffold.BumpDevice)
		}
	}

	return r
}

func ginMode(mode string) string {
	switch mode {
	case gin.ReleaseMode, gin.TestMode, gin.DebugMode:
		return mode
	default:
		return gin.DebugMode
	}
}
