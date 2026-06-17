// Package wire 手工依赖注入装配（沿用 web-go 约定：手动编辑，不用 wire 代码生成）。
package wire

import (
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/redisx"
	"github.com/pysinsjz/vulture-gateway/router"
)

// App 持有装配完成的运行期对象。
type App struct {
	Engine *gin.Engine
	Redis  *redis.Client
}

// WireApp 按层级顺序手工装配：Redis → 签发器/吊销存储 → 中间件 → handler → router。
func WireApp(cfg *config.Configuration) *App {
	rdb := redisx.NewClient(cfg.Redis)

	signer := auth.NewSigner(cfg.JWT)
	tvs := auth.NewTokenVersionStore(rdb)

	jwtAuth := middleware.JWTAuth(signer, tvs, middleware.DefaultPublicPaths)

	probeHandler := handler.NewProbeHandler()
	scaffoldHandler := handler.NewScaffoldHandler(signer, tvs)

	engine := router.NewRouter(cfg, probeHandler, scaffoldHandler, jwtAuth)

	return &App{Engine: engine, Redis: rdb}
}
