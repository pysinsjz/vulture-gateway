package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Configuration 是网关的全量配置。分环境 YAML（dev/test/staging/prod）落在 config/ 目录，
// 通过 APP_ENV 选择；敏感项可由环境变量覆盖（前缀 VG_，点号转下划线，如 VG_JWT_SECRET）。
type Configuration struct {
	Env          string             `mapstructure:"env"`
	Server       ServerConfig       `mapstructure:"server"`
	Redis        RedisConfig        `mapstructure:"redis"`
	Postgres     PostgresConfig     `mapstructure:"postgres"`
	JWT          JWTConfig          `mapstructure:"jwt"`
	OAuth        OAuthConfig        `mapstructure:"oauth"`
	ClawHub      ClawHubConfig      `mapstructure:"clawhub"`
	LLM          LLMConfig          `mapstructure:"llm"`
	Distribution DistributionConfig `mapstructure:"distribution"`
	Bootstrap    BootstrapConfig    `mapstructure:"bootstrap"`
	Scaffold     ScaffoldConfig     `mapstructure:"scaffold"`
}

// BootstrapConfig 启动引导聚合端点配置（#28，F2）。
// feature_flags 为类型化注册表：max_upload_mb 派生自 llm.max_request_bytes，此处只配 mcp_enabled。
type BootstrapConfig struct {
	GatewayVersion string        `mapstructure:"gateway_version"` // 网关版本（报障/兼容判断）
	MinAppVersion  string        `mapstructure:"min_app_version"` // 最低建议 App 版本（低于视为强更提示）
	McpEnabled     bool          `mapstructure:"mcp_enabled"`     // feature_flag：E 域 MCP 入口，默认 false
	Notices        []NoticeEntry `mapstructure:"notices"`         // 运营公告（按窗口过滤后下发）
}

// NoticeEntry 是一条运营公告。StartsAt/EndsAt 为 0 表示该侧不设边界。
type NoticeEntry struct {
	ID       string `mapstructure:"id"`
	Level    string `mapstructure:"level"` // info | warning | critical
	Title    string `mapstructure:"title"`
	Content  string `mapstructure:"content"`
	StartsAt int64  `mapstructure:"starts_at"` // Unix 秒；未到不展示
	EndsAt   int64  `mapstructure:"ends_at"`   // Unix 秒；已过不展示
	URL      string `mapstructure:"url"`
}

// DistributionConfig 宿主 App 自更新发布清单（#27，F1）。
// 发布元数据为占位注入（ops/CD 维护），App 二进制存 R2、下载直连不经网关。
// TODO(ops): 真实发布管线（CI 上传 R2 + 注册）接入后由其填充。
type DistributionConfig struct {
	Releases []ReleaseEntry `mapstructure:"releases"`
}

// ReleaseEntry 是一条 (channel, platform) 的发布记录。
type ReleaseEntry struct {
	Channel      string `mapstructure:"channel"`       // stable / beta
	Platform     string `mapstructure:"platform"`      // darwin-arm64 / darwin-x64 / win32-x64
	Version      string `mapstructure:"version"`       // 该发布的逻辑版本（semver）
	Mandatory    bool   `mapstructure:"mandatory"`     // 强更提示标记（仅提示，网关不硬门禁）
	MinVersion   string `mapstructure:"min_version"`   // 低于此版本视为强更提示
	DownloadURL  string `mapstructure:"download_url"`  // R2 直连下载地址
	Checksum     string `mapstructure:"checksum"`      // "sha256:..." 完整性校验
	Size         int64  `mapstructure:"size"`          // 安装包字节数
	ReleaseNotes string `mapstructure:"release_notes"` // 更新说明
}

// LLMConfig LLM 代理（litellm proxy，ADR-0005）转发配置。
// 网关持有 litellm virtual key，转发时注入 Authorization，桌面端永远拿不到。
type LLMConfig struct {
	BaseURL    string        `mapstructure:"base_url"`    // litellm 基址，如 http://127.0.0.1:4000
	VirtualKey string        `mapstructure:"virtual_key"` // litellm virtual key（VG_LLM_VIRTUAL_KEY 注入；空则不带鉴权头）
	Timeout    time.Duration `mapstructure:"timeout"`     // 非流式（如 /v1/models）转发超时，默认 30s
	// 以下为流式推理（/v1/chat/completions，#24）双超时（ADR-0008）：
	StreamIdleTimeout    time.Duration `mapstructure:"stream_idle_timeout"`    // chunk 间空闲上限，默认 120s
	StreamRequestTimeout time.Duration `mapstructure:"stream_request_timeout"` // 单请求总时长上限，默认 30m
	// 前置门禁（#25）：
	MaxRequestBytes int64 `mapstructure:"max_request_bytes"` // chat 请求体上限（含多模态 base64），默认 25MB；>上限 413
	// StubNoSubscription 占位（#25）：true=桩判定所有用户无有效订阅→402。
	// TODO(计费 C 域): 待真实 Subscription 接入后移除，订阅状态改为查计费域。
	StubNoSubscription bool `mapstructure:"stub_no_subscription"`
	// 计量与额度（#26，ADR-0008）。配额/定价为占位，TODO(计费 C 域)待真实数值接入。
	Window5hCap               int64   `mapstructure:"window_5h_cap"`                // 5h 窗 Credit 上限；<=0 不限
	WindowWeekCap             int64   `mapstructure:"window_week_cap"`              // 周窗 Credit 上限；<=0 不限
	CreditsPerPromptToken     float64 `mapstructure:"credits_per_prompt_token"`     // prompt token→Credit 折算率，默认 1
	CreditsPerCompletionToken float64 `mapstructure:"credits_per_completion_token"` // completion token→Credit 折算率，默认 1
}

// ClawHubConfig 内网 ClawHub（fork 裁剪版注册中心，ADR-0006）转发配置。
// ClawHub 纯内网、无鉴权；网关鉴权后转发 skill/plugin 查询到此基址。
type ClawHubConfig struct {
	BaseURL string        `mapstructure:"base_url"` // 内网基址，如 http://clawhub.internal:3210
	Timeout time.Duration `mapstructure:"timeout"`  // 转发请求超时，默认 10s
}

// PostgresConfig 数据库连接（ADR-0001：用 PostgreSQL，非 web-go 默认的 MySQL）。
type PostgresConfig struct {
	DSN string `mapstructure:"dsn"` // 完整 DSN，如 host=... user=... dbname=... sslmode=disable
}

// OAuthConfig 网关作为 OAuth 授权服务器（ADR-0009）的配置。
type OAuthConfig struct {
	ClientID           string         `mapstructure:"client_id"`            // 期望的桌面端 client_id，固定 vulture-desktop
	GatewayBaseURL     string         `mapstructure:"gateway_base_url"`     // 网关外部基址，用于拼上游回调 URL
	GWCodeTTL          time.Duration  `mapstructure:"gw_code_ttl"`          // GW_CODE 寿命，默认 60s
	AuthzTTL           time.Duration  `mapstructure:"authz_ttl"`            // authorize 暂存寿命，默认 10m
	RefreshTTL         time.Duration  `mapstructure:"refresh_ttl"`          // refresh token 滑动寿命，默认 60d
	RefreshGraceWindow time.Duration  `mapstructure:"refresh_grace_window"` // refresh 轮换幂等宽限窗，默认 60s
	Upstream           UpstreamConfig `mapstructure:"upstream"`
}

// UpstreamConfig 上游 Identity Provider（Casdoor）对接配置。
// Mode=stub 时用内置桩（#11 联调）；Mode=oidc 时走真实 Casdoor（凭据由 #10 填入）。
type UpstreamConfig struct {
	Mode         string `mapstructure:"mode"`          // stub | oidc
	Issuer       string `mapstructure:"issuer"`        // oidc 模式：OIDC issuer，端点经 discovery 自得（ADR-0012）
	AuthorizeURL string `mapstructure:"authorize_url"` // stub 模式：桩 authorize 端点
	TokenURL     string `mapstructure:"token_url"`     // 仅 stub 保留；oidc 由 discovery 提供
	ClientID     string `mapstructure:"client_id"`     // 网关在上游注册的 client_id
	ClientSecret string `mapstructure:"client_secret"` // 由 VG_OAUTH_UPSTREAM_CLIENT_SECRET 注入
	Scopes       string `mapstructure:"scopes"`        // 空格分隔，如 "openid profile"
}

// ServerConfig HTTP 服务监听配置。
type ServerConfig struct {
	Addr string `mapstructure:"addr"` // 监听地址，如 ":8080"
	Mode string `mapstructure:"mode"` // gin 模式：debug / release / test
}

// RedisConfig Redis 连接配置（即时吊销的 token_version 存储，ADR-0010）。
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// JWTConfig access JWT 签发/校验配置。
type JWTConfig struct {
	Secret    string        `mapstructure:"secret"`     // HS256 对称密钥
	Issuer    string        `mapstructure:"issuer"`     // iss claim
	AccessTTL time.Duration `mapstructure:"access_ttl"` // access JWT 寿命，默认 30m
}

// ScaffoldConfig 脚手架开关。Enabled 时挂载 /__dev/* 内部签发端点，仅供 dev/test 端到端验证，
// 生产必须关闭。
type ScaffoldConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// Load 按环境读取 config/config.<env>.yaml，并应用默认值与 VG_ 前缀的环境变量覆盖。
// env 为空时默认 "dev"。
func Load(env string) (*Configuration, error) {
	if env == "" {
		env = "dev"
	}

	v := viper.New()
	v.SetConfigName("config." + env)
	v.SetConfigType("yaml")
	v.AddConfigPath("config")
	v.AddConfigPath(".")

	setDefaults(v)

	v.SetEnvPrefix("VG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("读取配置 config.%s.yaml 失败: %w", env, err)
	}

	var cfg Configuration
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	cfg.Env = env

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.addr", ":8080")
	v.SetDefault("server.mode", "debug")
	v.SetDefault("redis.addr", "127.0.0.1:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("jwt.issuer", "vulture-gateway")
	v.SetDefault("jwt.access_ttl", "30m")
	v.SetDefault("scaffold.enabled", false)
	v.SetDefault("oauth.client_id", "vulture-desktop")
	v.SetDefault("oauth.gateway_base_url", "http://127.0.0.1:8080")
	v.SetDefault("oauth.gw_code_ttl", "60s")
	v.SetDefault("oauth.authz_ttl", "10m")
	v.SetDefault("oauth.refresh_ttl", "1440h") // 60 天
	v.SetDefault("oauth.refresh_grace_window", "60s")
	v.SetDefault("oauth.upstream.mode", "stub")
	v.SetDefault("oauth.upstream.scopes", "openid profile")
	v.SetDefault("clawhub.base_url", "http://127.0.0.1:3210")
	v.SetDefault("clawhub.timeout", "10s")
	v.SetDefault("llm.base_url", "http://127.0.0.1:4000")
	v.SetDefault("llm.timeout", "30s")
	v.SetDefault("llm.stream_idle_timeout", "120s")
	v.SetDefault("llm.stream_request_timeout", "30m")
	v.SetDefault("llm.max_request_bytes", 25*1024*1024) // 25MB
	v.SetDefault("llm.credits_per_prompt_token", 1.0)
	v.SetDefault("llm.credits_per_completion_token", 1.0)
	v.SetDefault("bootstrap.gateway_version", "0.1.0-dev")
}

func (c *Configuration) validate() error {
	if c.JWT.Secret == "" {
		return fmt.Errorf("jwt.secret 未配置（可由 VG_JWT_SECRET 提供）")
	}
	if c.JWT.AccessTTL <= 0 {
		return fmt.Errorf("jwt.access_ttl 必须为正，当前 %s", c.JWT.AccessTTL)
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("redis.addr 未配置")
	}
	if c.OAuth.ClientID == "" {
		return fmt.Errorf("oauth.client_id 未配置")
	}
	if c.OAuth.GatewayBaseURL == "" {
		return fmt.Errorf("oauth.gateway_base_url 未配置")
	}
	if c.OAuth.GWCodeTTL <= 0 || c.OAuth.AuthzTTL <= 0 || c.OAuth.RefreshTTL <= 0 || c.OAuth.RefreshGraceWindow <= 0 {
		return fmt.Errorf("oauth.gw_code_ttl / authz_ttl / refresh_ttl / refresh_grace_window 必须为正")
	}
	switch c.OAuth.Upstream.Mode {
	case "stub":
	case "oidc":
		if c.OAuth.Upstream.Issuer == "" {
			return fmt.Errorf("oauth.upstream.issuer 未配置（oidc 模式必填）")
		}
		if c.OAuth.Upstream.ClientID == "" {
			return fmt.Errorf("oauth.upstream.client_id 未配置（oidc 模式必填）")
		}
		if c.OAuth.Upstream.ClientSecret == "" {
			return fmt.Errorf("oauth.upstream.client_secret 未配置（由 VG_OAUTH_UPSTREAM_CLIENT_SECRET 注入）")
		}
	default:
		return fmt.Errorf("oauth.upstream.mode 必须为 stub 或 oidc，当前 %q", c.OAuth.Upstream.Mode)
	}
	if c.ClawHub.BaseURL == "" {
		return fmt.Errorf("clawhub.base_url 未配置")
	}
	if c.ClawHub.Timeout <= 0 {
		return fmt.Errorf("clawhub.timeout 必须为正，当前 %s", c.ClawHub.Timeout)
	}
	if c.LLM.BaseURL == "" {
		return fmt.Errorf("llm.base_url 未配置")
	}
	if c.LLM.Timeout <= 0 {
		return fmt.Errorf("llm.timeout 必须为正，当前 %s", c.LLM.Timeout)
	}
	return nil
}
