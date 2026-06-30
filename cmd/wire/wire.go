// Package wire 手工依赖注入装配（沿用 web-go 约定：手动编辑，不用 wire 代码生成）。
package wire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/auth"
	"github.com/pysinsjz/vulture-gateway/internal/auth/signin"
	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/db"
	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/notify"
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

// wireOptions 承接装配期可覆盖项。生产路径不传任何 Option（全走真实 GORM DAO）；
// 测试在 router 级 HTTP 缝注入内存身份/用户仓，使「设密码→密码登录」端到端回路无需真实 PostgreSQL。
type wireOptions struct {
	identities dao.IdentityRepository
	users      dao.UserRepository
	transactor dao.Transactor
}

// Option 微调 WireApp 装配（仅测试用）。
type Option func(*wireOptions)

// WithIdentityRepository 覆盖 IdentityRepository（测试注入内存实现）。
func WithIdentityRepository(r dao.IdentityRepository) Option {
	return func(o *wireOptions) { o.identities = r }
}

// WithUserRepository 覆盖 UserRepository（测试注入内存实现）。
func WithUserRepository(r dao.UserRepository) Option {
	return func(o *wireOptions) { o.users = r }
}

// WithTransactor 覆盖事务器（测试注入透传实现，使账号级写入无需真实 PostgreSQL 事务）。
func WithTransactor(tx dao.Transactor) Option {
	return func(o *wireOptions) { o.transactor = tx }
}

// WireApp 按层级顺序手工装配：DB/Redis → 签发器/吊销存储/授权暂存 → DAO → handler → router。
func WireApp(cfg *config.Configuration, opts ...Option) (*App, error) {
	var wo wireOptions
	for _, o := range opts {
		o(&wo)
	}

	rdb := redisx.NewClient(cfg.Redis)

	gdb, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("装配 PostgreSQL 失败: %w", err)
	}

	signer := auth.NewSigner(cfg.JWT)
	tvs := auth.NewTokenVersionStore(rdb)

	authzStore := auth.NewAuthzStore(rdb, cfg.OAuth.AuthzTTL)
	gwCodeStore := auth.NewGWCodeStore(rdb, cfg.OAuth.GWCodeTTL)
	passwordLinkStore := auth.NewPasswordLinkStore(rdb, cfg.OAuth.PasswordLinkTTL)
	replayStore := auth.NewRefreshReplayStore(rdb, cfg.OAuth.RefreshGraceWindow)
	locker := auth.NewLocker(rdb)

	transactor := dao.NewTransactor(gdb)
	if wo.transactor != nil {
		transactor = wo.transactor
	}
	userDAO := dao.NewUserDAO(gdb)
	deviceDAO := dao.NewDeviceDAO(gdb)
	refreshDAO := dao.NewRefreshTokenDAO(gdb)
	identityDAO := dao.NewIdentityDAO(gdb)
	// 测试注入点：用内存身份/用户仓替换真实 GORM DAO，让 router 级 HTTP 缝可跑端到端回路（无需 PostgreSQL）。
	if wo.identities != nil {
		identityDAO = wo.identities
	}
	if wo.users != nil {
		userDAO = wo.users
	}

	// 自建身份认证（ADR-0013）：RSA 解密（dev 缺省自生成临时密钥）+ 验证码/限流/CSRF 存储。
	rsaDecryptor, err := buildRSADecryptor(cfg.Auth.RSAPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("装配 RSA 解密器失败: %w", err)
	}
	hasher := auth.NewBcryptHasher(cfg.Auth.BcryptCost)
	// 万能验证码后门仅在 dev/test 注入；其余环境强制为空（与 config.validate 双重保险）。
	otpBypassCode := ""
	if cfg.Env == "dev" || cfg.Env == "test" {
		otpBypassCode = cfg.Auth.DevOTPBypassCode
	}
	otpStore := auth.NewOTPStore(rdb, cfg.Auth.OTPTTL, cfg.Auth.OTPResendInterval, cfg.Auth.OTPMaxAttempts, otpBypassCode)
	csrfStore := auth.NewCSRFStore(rdb, cfg.Auth.CSRFTTL)
	rateLimiter := auth.NewRateLimiter(rdb, auth.RateLimitConfig{
		LoginMaxFailures: cfg.Auth.LoginMaxFailures,
		LoginLockWindow:  cfg.Auth.LoginLockWindow,
		SendMax:          cfg.Auth.SendMax,
		SendWindow:       cfg.Auth.SendWindow,
	})

	// 验证码渠道：email 优先用 config seed 的 SMTP，否则 stub；sms Phase 1 用 stub（无真实短信适配器）。
	otpService := service.NewOTPService(otpStore, rateLimiter, map[string]notify.CodeSender{
		model.ProviderCategoryEmail: buildEmailSender(cfg.Auth.Providers),
		model.ProviderCategorySMS:   notify.NewStubSender("sms"),
	})

	// 登录方式 registry：password + email_code + sms_code（Phase 1 全为 Direct）。
	signinRegistry := signin.NewRegistry(
		signin.NewPasswordMethod(identityDAO, hasher, rsaDecryptor, rateLimiter),
		signin.NewEmailCodeMethod(otpStore, identityDAO, userDAO, transactor),
		signin.NewSmsCodeMethod(otpStore, identityDAO, userDAO, transactor),
	)

	oauthService := service.NewOAuthService(transactor, deviceDAO, refreshDAO, gwCodeStore, tvs, replayStore, locker, signer, cfg.OAuth.RefreshTTL, cfg.OAuth.RefreshGraceWindow)
	deviceService := service.NewDeviceService(tvs, deviceDAO, refreshDAO)

	clawHubClient := clawhub.NewHTTPClient(cfg.ClawHub.BaseURL, &http.Client{Timeout: cfg.ClawHub.Timeout})
	pluginService := service.NewPluginService(clawHubClient)
	skillService := service.NewSkillService(clawHubClient)
	telemetryService := service.NewTelemetryService(clawHubClient)

	// ADR-0014：Proxy/Admin 双客户端角色分离。Proxy 转发推理（每用户注入 virtual key）；
	// Admin 持 Master Key 签发/删用户 key，永不转发推理。
	llmClient := litellm.NewHTTPClient(cfg.LLM.BaseURL, &http.Client{Timeout: cfg.LLM.Timeout})
	llmAdminClient := litellm.NewAdminClient(cfg.LLM.BaseURL, cfg.LLM.MasterKey, &http.Client{Timeout: cfg.LLM.Timeout})
	// 用户 virtual key get-or-create：DB 真相源 + Redis 缓存热路径 + 复用 auth.Locker 做分布式锁防双签。
	vkeyDAO := dao.NewUserVirtualKeyDAO(gdb)
	vkeyCache := service.NewRedisVKeyCache(rdb, cfg.LLM.VKeyCacheTTL)
	virtualKeyService := service.NewVirtualKeyService(vkeyDAO, llmAdminClient, vkeyCache, locker, cfg.LLM.DefaultTeamAlias)
	llmService := service.NewLLMService(llmClient, virtualKeyService)
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

	probeHandler := handler.NewProbeHandler(identityDAO)
	scaffoldHandler := handler.NewScaffoldHandler(signer, tvs)
	oauthHandler := handler.NewOAuthHandler(authzStore, gwCodeStore, userDAO, oauthService, cfg.OAuth.ClientID)
	loginHandler := handler.NewLoginHandler(signinRegistry, otpService, authzStore, gwCodeStore, userDAO, virtualKeyService, rsaDecryptor, csrfStore, cfg.Auth.AllowPlaintextPassword)
	// 设/改密（ADR-0015 / #39、#40）：service 编排解密+策略+（改密）pwreset 验码+失败限流+账号级写入；
	// handler 承接 Bearer 铸链、托管页与改密发码。otp/limiter 复用登录链路同一组件。
	passwordService := service.NewPasswordService(identityDAO, hasher, rsaDecryptor, transactor, otpStore, rateLimiter)
	passwordHandler := handler.NewPasswordHandler(passwordService, otpService, passwordLinkStore, csrfStore, rsaDecryptor, cfg.OAuth.GatewayBaseURL, cfg.Auth.AllowPlaintextPassword)
	deviceHandler := handler.NewDeviceHandler(signer, deviceService)
	// 下载代理（interim）：把内网 ClawHub 制品字节经网关回传桌面端（路线 A 伪预签名）。客户端无超时，
	// 由请求 ctx 约束生命周期；待 ClawHub 路线 B（MinIO 真预签名、公网可达）落地后改回直接 302。
	downloadProxy := handler.NewDownloadProxy(&http.Client{})
	pluginHandler := handler.NewPluginHandler(pluginService, downloadProxy)
	skillHandler := handler.NewSkillHandler(skillService, downloadProxy)
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

	engine := router.NewRouter(cfg, probeHandler, scaffoldHandler, oauthHandler, loginHandler, passwordHandler, deviceHandler, pluginHandler, skillHandler, telemetryHandler, llmHandler, distributionHandler, bootstrapHandler, jwtAuth, jwtAuthLLM)

	return &App{Engine: engine, Redis: rdb, DB: gdb}, nil
}

// buildRSADecryptor 构造密码解密器。私钥为空时（dev/test）自生成临时 RSA 密钥对，重启即换。
func buildRSADecryptor(privPEM string) (*auth.RSADecryptor, error) {
	if privPEM == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("生成临时 RSA 密钥失败: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("序列化临时 RSA 私钥失败: %w", err)
		}
		privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		log.Println("[auth] 未配置 auth.rsa_private_key_pem，已生成临时 RSA 密钥对（仅 dev/test，重启即换）")
	}
	return auth.NewRSADecryptor(privPEM)
}

// buildEmailSender 选取邮件发送器：config seed 含启用的 SMTP provider 则用之，否则用 stub（dev 联调）。
func buildEmailSender(seeds []config.ProviderSeed) notify.CodeSender {
	for _, s := range seeds {
		if s.Category == model.ProviderCategoryEmail && s.Type == "smtp" && s.Enabled && s.Host != "" {
			return notify.NewSMTPSender(s.Host, s.Port, s.Username, s.Password, s.From)
		}
	}
	return notify.NewStubSender("email")
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
