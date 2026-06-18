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
	jwtAuth gin.HandlerFunc,
) *gin.Engine {
	gin.SetMode(ginMode(cfg.Server.Mode))

	r := gin.New()
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
		// plugin 列表：鉴权后转发内网 ClawHub /packages（#19 曳光弹；端点翻译铺满见 #20）。
		v1.GET("/plugins", plugin.ListPlugins)
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
