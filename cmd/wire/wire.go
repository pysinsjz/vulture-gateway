// Package wire 手工依赖注入装配（沿用 web-go 约定：手动编辑，不用 wire 代码生成）。
package wire

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/db"
	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/redisx"
	"github.com/pysinsjz/vulture-gateway/internal/service"
	"github.com/pysinsjz/vulture-gateway/router"
)

// App 持有装配完成的运行期对象。
type App struct {
	Engine *gin.Engine
	Redis  *redis.Client
	DB     *gorm.DB
}

// WireApp 按层级顺序手工装配：DB/Redis → 签发器/吊销存储/上游/授权暂存 → DAO → handler → router。
func WireApp(cfg *config.Configuration) (*App, error) {
	rdb := redisx.NewClient(cfg.Redis)

	gdb, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("装配 PostgreSQL 失败: %w", err)
	}

	signer := auth.NewSigner(cfg.JWT)
	tvs := auth.NewTokenVersionStore(rdb)

	upstream, err := auth.NewUpstream(cfg.OAuth)
	if err != nil {
		return nil, fmt.Errorf("装配上游 IdP 失败: %w", err)
	}
	authzStore := auth.NewAuthzStore(rdb, cfg.OAuth.AuthzTTL)
	gwCodeStore := auth.NewGWCodeStore(rdb, cfg.OAuth.GWCodeTTL)
	replayStore := auth.NewRefreshReplayStore(rdb, cfg.OAuth.RefreshGraceWindow)
	locker := auth.NewLocker(rdb)

	transactor := dao.NewTransactor(gdb)
	userDAO := dao.NewUserDAO(gdb)
	deviceDAO := dao.NewDeviceDAO(gdb)
	refreshDAO := dao.NewRefreshTokenDAO(gdb)

	oauthService := service.NewOAuthService(transactor, deviceDAO, refreshDAO, gwCodeStore, tvs, replayStore, locker, signer, cfg.OAuth.RefreshTTL, cfg.OAuth.RefreshGraceWindow)
	deviceService := service.NewDeviceService(tvs, deviceDAO, refreshDAO)

	clawHubClient := clawhub.NewHTTPClient(cfg.ClawHub.BaseURL, &http.Client{Timeout: cfg.ClawHub.Timeout})
	pluginService := service.NewPluginService(clawHubClient)

	jwtAuth := middleware.JWTAuth(signer, tvs, middleware.DefaultPublicPaths)

	probeHandler := handler.NewProbeHandler()
	scaffoldHandler := handler.NewScaffoldHandler(signer, tvs)
	oauthHandler := handler.NewOAuthHandler(upstream, authzStore, gwCodeStore, userDAO, oauthService, cfg.OAuth.ClientID)
	deviceHandler := handler.NewDeviceHandler(signer, deviceService)
	pluginHandler := handler.NewPluginHandler(pluginService)

	engine := router.NewRouter(cfg, probeHandler, scaffoldHandler, oauthHandler, deviceHandler, pluginHandler, jwtAuth)

	return &App{Engine: engine, Redis: rdb, DB: gdb}, nil
}
