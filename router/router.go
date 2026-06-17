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
	jwtAuth gin.HandlerFunc,
) *gin.Engine {
	gin.SetMode(ginMode(cfg.Server.Mode))

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	v1.Use(jwtAuth)
	{
		v1.GET("/whoami", probe.Whoami)
		// 公开例外：JWTAuth 放行（见 middleware.DefaultPublicPaths），属其它域的占位实现。
		v1.GET("/bootstrap", probe.BootstrapStub)
		v1.GET("/app/latest", probe.AppLatestStub)
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
