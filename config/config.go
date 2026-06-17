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
	JWT      JWTConfig      `mapstructure:"jwt"`
	Scaffold ScaffoldConfig `mapstructure:"scaffold"`
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
	return nil
}
