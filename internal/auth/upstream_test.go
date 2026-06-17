package auth

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/pysinsjz/vulture-gateway/config"
)

func stubCfg() config.OAuthConfig {
	return config.OAuthConfig{
		GatewayBaseURL: "http://127.0.0.1:8080",
		Upstream: config.UpstreamConfig{
			Mode:         "stub",
			AuthorizeURL: "https://idp.example/authorize",
			ClientID:     "vulture-gateway",
			Scopes:       "openid profile",
		},
	}
}

func TestNewUpstream_ModeSelection(t *testing.T) {
	if _, err := NewUpstream(stubCfg()); err != nil {
		t.Errorf("stub 模式应成功, err=%v", err)
	}

	oidc := stubCfg()
	oidc.Upstream.Mode = "oidc"
	if _, err := NewUpstream(oidc); err == nil {
		t.Error("oidc 模式当前应返回未接入错误")
	}

	bad := stubCfg()
	bad.Upstream.Mode = "garbage"
	if _, err := NewUpstream(bad); err == nil {
		t.Error("未知 mode 应报错")
	}
}

func TestStubUpstream_AuthorizeURL(t *testing.T) {
	up, err := NewUpstream(stubCfg())
	if err != nil {
		t.Fatalf("NewUpstream 失败: %v", err)
	}
	raw := up.AuthorizeURL("st_link123")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthorizeURL 非法: %v", err)
	}
	if !strings.HasPrefix(raw, "https://idp.example/authorize?") {
		t.Errorf("应基于配置的 authorize_url, 实际 %s", raw)
	}
	q := u.Query()
	if q.Get("state") != "st_link123" {
		t.Errorf("应携带关联 state, 实际 %q", q.Get("state"))
	}
	if q.Get("redirect_uri") != "http://127.0.0.1:8080/oauth/callback/casdoor" {
		t.Errorf("回调地址不符: %q", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" || q.Get("client_id") != "vulture-gateway" {
		t.Errorf("response_type/client_id 不符: %s", u.RawQuery)
	}
}

func TestStubUpstream_Exchange(t *testing.T) {
	up, _ := NewUpstream(stubCfg())
	sub, err := up.Exchange(context.Background(), "CODE1")
	if err != nil {
		t.Fatalf("Exchange 失败: %v", err)
	}
	if sub != "stub-subject:CODE1" {
		t.Errorf("subject 不符: %q", sub)
	}
	if _, err := up.Exchange(context.Background(), ""); err == nil {
		t.Error("空 code 应报错")
	}
}
