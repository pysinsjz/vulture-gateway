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
	Env      string         `mapstructure:"env"`
	Server   ServerConfig   `mapstructure:"server"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Postgres PostgresConfig `mapstructure:"postgres"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	OAuth    OAuthConfig    `mapstructure:"oauth"`
	Scaffold ScaffoldConfig `mapstructure:"scaffold"`
}

// PostgresConfig 数据库连接（ADR-0001：用 PostgreSQL，非 web-go 默认的 MySQL）。
type PostgresConfig struct {
	DSN string `mapstructure:"dsn"` // 完整 DSN，如 host=... user=... dbname=... sslmode=disable
}

// OAuthConfig 网关作为 OAuth 授权服务器（ADR-0009）的配置。
type OAuthConfig struct {
	ClientID       string         `mapstructure:"client_id"`        // 期望的桌面端 client_id，固定 vulture-desktop
	GatewayBaseURL string         `mapstructure:"gateway_base_url"` // 网关外部基址，用于拼上游回调 URL
	GWCodeTTL      time.Duration  `mapstructure:"gw_code_ttl"`      // GW_CODE 寿命，默认 60s
	AuthzTTL       time.Duration  `mapstructure:"authz_ttl"`        // authorize 暂存寿命，默认 10m
	RefreshTTL     time.Duration  `mapstructure:"refresh_ttl"`      // refresh token 滑动寿命，默认 60d
	Upstream       UpstreamConfig `mapstructure:"upstream"`
}

// UpstreamConfig 上游 Identity Provider（Casdoor）对接配置。
// Mode=stub 时用内置桩（#11 联调）；Mode=oidc 时走真实 Casdoor（凭据由 #10 填入）。
type UpstreamConfig struct {
	Mode         string `mapstructure:"mode"`          // stub | oidc
	AuthorizeURL string `mapstructure:"authorize_url"` // 上游 authorize 端点
	TokenURL     string `mapstructure:"token_url"`     // 上游 token 端点
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
	v.SetDefault("oauth.upstream.mode", "stub")
	v.SetDefault("oauth.upstream.scopes", "openid profile")
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
	if c.OAuth.GWCodeTTL <= 0 || c.OAuth.AuthzTTL <= 0 || c.OAuth.RefreshTTL <= 0 {
		return fmt.Errorf("oauth.gw_code_ttl / authz_ttl / refresh_ttl 必须为正")
	}
	switch c.OAuth.Upstream.Mode {
	case "stub", "oidc":
	default:
		return fmt.Errorf("oauth.upstream.mode 必须为 stub 或 oidc，当前 %q", c.OAuth.Upstream.Mode)
	}
	return nil
}
