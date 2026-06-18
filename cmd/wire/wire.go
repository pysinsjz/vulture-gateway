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
	"github.com/pysinsjz/vulture-gateway/internal/litellm"
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
	skillService := service.NewSkillService(clawHubClient)
	telemetryService := service.NewTelemetryService(clawHubClient)

	llmClient := litellm.NewHTTPClient(cfg.LLM.BaseURL, cfg.LLM.VirtualKey, &http.Client{Timeout: cfg.LLM.Timeout})
	llmService := service.NewLLMService(llmClient)
	// 订阅检查为占位（#25）：active = !StubNoSubscription，待计费 C 域接入真实 Subscription。
	subChecker := service.NewStubSubscriptionChecker(!cfg.LLM.StubNoSubscription)
	// 计量与额度（#26）：ZSET 双窗（5h/周）+ 占位配额/定价，待计费 C 域接入真实数值。
	meteringService := service.NewMeteringService(rdb, []service.UsageWindow{
		{Name: service.Window5h, Size: service.Window5hSize, Cap: cfg.LLM.Window5hCap},
		{Name: service.WindowWeek, Size: service.WindowWeekSize, Cap: cfg.LLM.WindowWeekCap},
	}, service.Pricing{
		PromptCreditPerToken:     cfg.LLM.CreditsPerPromptToken,
		CompletionCreditPerToken: cfg.LLM.CreditsPerCompletionToken,
	})

	jwtAuth := middleware.JWTAuth(signer, tvs, middleware.DefaultPublicPaths)
	jwtAuthLLM := middleware.JWTAuthLLM(signer, tvs, nil)

	probeHandler := handler.NewProbeHandler()
	scaffoldHandler := handler.NewScaffoldHandler(signer, tvs)
	oauthHandler := handler.NewOAuthHandler(upstream, authzStore, gwCodeStore, userDAO, oauthService, cfg.OAuth.ClientID)
	deviceHandler := handler.NewDeviceHandler(signer, deviceService)
	pluginHandler := handler.NewPluginHandler(pluginService)
	skillHandler := handler.NewSkillHandler(skillService)
	telemetryHandler := handler.NewTelemetryHandler(telemetryService)
	llmHandler := handler.NewLLMHandler(llmService, subChecker, meteringService, cfg.LLM.StreamIdleTimeout, cfg.LLM.StreamRequestTimeout, cfg.LLM.MaxRequestBytes)

	// 宿主 App 自更新（#27）：发布清单由 config 注入占位，待 ops/CD 发布管线接入。
	distributionService := service.NewDistributionService(toReleases(cfg.Distribution.Releases))
	distributionHandler := handler.NewDistributionHandler(distributionService)

	// 启动引导聚合（#28）：max_upload_mb 派生自 LLM 请求体上限（与 /v1/* 413 一致）。
	maxUploadMB := cfg.LLM.MaxRequestBytes / (1024 * 1024)
	if maxUploadMB <= 0 {
		maxUploadMB = 25
	}
	bootstrapService := service.NewBootstrapService(cfg.Bootstrap.GatewayVersion, cfg.Bootstrap.MinAppVersion, cfg.Bootstrap.McpEnabled, maxUploadMB, toNotices(cfg.Bootstrap.Notices), distributionService)
	bootstrapHandler := handler.NewBootstrapHandler(bootstrapService)

	engine := router.NewRouter(cfg, probeHandler, scaffoldHandler, oauthHandler, deviceHandler, pluginHandler, skillHandler, telemetryHandler, llmHandler, distributionHandler, bootstrapHandler, jwtAuth, jwtAuthLLM)

	return &App{Engine: engine, Redis: rdb, DB: gdb}, nil
}

// toNotices 把 config 公告映射为 service 层视图。
func toNotices(entries []config.NoticeEntry) []service.Notice {
	out := make([]service.Notice, 0, len(entries))
	for _, e := range entries {
		out = append(out, service.Notice{
			ID:       e.ID,
			Level:    e.Level,
			Title:    e.Title,
			Content:  e.Content,
			StartsAt: e.StartsAt,
			EndsAt:   e.EndsAt,
			URL:      e.URL,
		})
	}
	return out
}

// toReleases 把 config 发布清单映射为 service 层视图（避免 service 依赖 config）。
func toReleases(entries []config.ReleaseEntry) []service.Release {
	out := make([]service.Release, 0, len(entries))
	for _, e := range entries {
		out = append(out, service.Release{
			Channel:      e.Channel,
			Platform:     e.Platform,
			Version:      e.Version,
			Mandatory:    e.Mandatory,
			MinVersion:   e.MinVersion,
			DownloadURL:  e.DownloadURL,
			Checksum:     e.Checksum,
			Size:         e.Size,
			ReleaseNotes: e.ReleaseNotes,
		})
	}
	return out
}
