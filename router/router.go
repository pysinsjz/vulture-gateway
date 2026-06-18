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
	device *handler.DeviceHandler,
	plugin *handler.PluginHandler,
	skill *handler.SkillHandler,
	telemetry *handler.TelemetryHandler,
	jwtAuth gin.HandlerFunc,
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

	// OAuth 端点（公开，不经 JWTAuth）。A1 上半：authorize + 上游回调（#11）。
	oauthGroup := r.Group("/oauth")
	{
		oauthGroup.GET("/authorize", oauth.Authorize)
		oauthGroup.GET("/callback/casdoor", oauth.Callback)
		oauthGroup.POST("/token", oauth.Token)
	}

	v1 := r.Group("/api/v1")
	v1.Use(jwtAuth)
	{
		v1.GET("/whoami", probe.Whoami)
		// 公开例外：JWTAuth 放行（见 middleware.DefaultPublicPaths）。
		v1.GET("/bootstrap", probe.BootstrapStub)
		v1.GET("/app/latest", probe.AppLatestStub)
		// logout 自带鉴权（公开例外）；devices 需 Bearer。
		v1.POST("/auth/logout", device.Logout)
		v1.GET("/devices", device.ListDevices)
		v1.DELETE("/devices/:device_id", device.DeleteDevice)
		// skill 族：鉴权后转发内网 ClawHub skills/skillVersions（#20）。
		v1.GET("/skills", skill.ListSkills)
		v1.GET("/skills/:slug", skill.GetSkill)
		v1.GET("/skills/:slug/versions", skill.ListSkillVersions)
		v1.GET("/skills/:slug/versions/:version", skill.GetSkillVersion)
		v1.GET("/skills/:slug/resolve", skill.ResolveSkill)
		v1.GET("/skills/:slug/download", skill.DownloadSkill)          // 302 跳 R2（#21）
		v1.POST("/skills/-/security-verdicts", skill.SecurityVerdicts) // 批量安全裁决（#22）
		// plugin 族：鉴权后转发内网 ClawHub packages/packageReleases（#19 list 曳光弹 + #20 铺满）。
		v1.GET("/plugins", plugin.ListPlugins)
		v1.GET("/plugins/:name", plugin.GetPlugin)
		v1.GET("/plugins/:name/versions/:version", plugin.GetPluginVersion)
		v1.GET("/plugins/:name/versions/:version/security", plugin.PluginSecurity)                  // 单查安装阻断（#22）
		v1.GET("/plugins/:name/download", plugin.DownloadPlugin)                                    // legacy-zip 302（#21）
		v1.GET("/plugins/:name/versions/:version/artifact/download", plugin.DownloadPluginArtifact) // npm-pack 302（#21）
		// 安装遥测（#22）：best-effort 转发内网 ClawHub 对账。
		v1.POST("/telemetry/install", telemetry.ReportInstall)
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
