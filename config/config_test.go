package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeConfig 在临时目录写一份 config/config.<env>.yaml 并切换工作目录到该临时目录。
func writeConfig(t *testing.T, env, body string) {
	t.Helper()
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("创建临时 config 目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config."+env+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("写临时配置失败: %v", err)
	}
	t.Chdir(dir)
}

func TestLoad_Success(t *testing.T) {
	writeConfig(t, "unittest", `
env: unittest
server:
  addr: ":9090"
  mode: release
redis:
  addr: "127.0.0.1:6380"
  db: 2
jwt:
  secret: "loaded-secret"
  access_ttl: "15m"
llm:
  default_team_alias: "team-pro"
scaffold:
  enabled: true
`)

	cfg, err := Load("unittest")
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Server.Addr != ":9090" {
		t.Errorf("server.addr = %q, 期望 :9090", cfg.Server.Addr)
	}
	if cfg.JWT.AccessTTL != 15*time.Minute {
		t.Errorf("jwt.access_ttl = %s, 期望 15m", cfg.JWT.AccessTTL)
	}
	if cfg.Redis.DB != 2 {
		t.Errorf("redis.db = %d, 期望 2", cfg.Redis.DB)
	}
	if !cfg.Scaffold.Enabled {
		t.Error("scaffold.enabled 期望 true")
	}
	if cfg.JWT.Issuer != "vulture-gateway" {
		t.Errorf("jwt.issuer 应取默认 vulture-gateway, 实际 %q", cfg.JWT.Issuer)
	}
}

func TestLoad_EnvOverridesSecret(t *testing.T) {
	writeConfig(t, "unittest", `
env: unittest
jwt:
  secret: ""
llm:
  default_team_alias: "team-pro"
`)
	t.Setenv("VG_JWT_SECRET", "from-env")

	cfg, err := Load("unittest")
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.JWT.Secret != "from-env" {
		t.Errorf("jwt.secret = %q, 期望 from-env（环境变量覆盖）", cfg.JWT.Secret)
	}
}

func TestLoad_RejectsEmptySecret(t *testing.T) {
	writeConfig(t, "unittest", `
env: unittest
jwt:
  secret: ""
`)

	if _, err := Load("unittest"); err == nil {
		t.Fatal("空 jwt.secret 应返回错误")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := Load("doesnotexist"); err == nil {
		t.Fatal("缺失配置文件应返回错误")
	}
}

// 明文密码旁路是 dev/test 后门，prod/staging 不得开启。校验由 Configuration.validate 强制顶住。
func TestLoad_RejectsAllowPlaintextPasswordInProd(t *testing.T) {
	writeConfig(t, "prod", `
env: prod
jwt:
  secret: "prod-secret"
auth:
  rsa_private_key_pem: "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----"
  allow_plaintext_password: true
llm:
  master_key: "ml-key"
  default_team_alias: "team-free"
`)

	if _, err := Load("prod"); err == nil {
		t.Fatal("prod 开启 allow_plaintext_password 应启动失败")
	}
}

func TestLoad_RejectsAllowPlaintextPasswordInStaging(t *testing.T) {
	writeConfig(t, "staging", `
env: staging
jwt:
  secret: "staging-secret"
auth:
  rsa_private_key_pem: "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----"
  allow_plaintext_password: true
llm:
  master_key: "ml-key"
  default_team_alias: "team-free"
`)

	if _, err := Load("staging"); err == nil {
		t.Fatal("staging 开启 allow_plaintext_password 应启动失败")
	}
}

func TestLoad_AllowsPlaintextPasswordInDev(t *testing.T) {
	writeConfig(t, "dev", `
env: dev
jwt:
  secret: "dev-secret"
auth:
  allow_plaintext_password: true
llm:
  default_team_alias: "team-pro"
`)

	cfg, err := Load("dev")
	if err != nil {
		t.Fatalf("dev 允许 allow_plaintext_password，Load 不应失败: %v", err)
	}
	if !cfg.Auth.AllowPlaintextPassword {
		t.Error("auth.allow_plaintext_password 应为 true")
	}
}

// ADR-0016：llm.default_team_alias 所有环境必填，缺失则启动失败（fail-loud 防 prod 漏配静默回退）。
func TestLoad_RejectsEmptyDefaultTeamAlias(t *testing.T) {
	writeConfig(t, "unittest", `
env: unittest
jwt:
  secret: "loaded-secret"
`)
	if _, err := Load("unittest"); err == nil {
		t.Fatal("空 llm.default_team_alias 应返回错误")
	}
}
