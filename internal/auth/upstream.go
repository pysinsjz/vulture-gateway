package auth

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pysinsjz/vulture-gateway/config"
)

// UpstreamIDP 抽象上游 Identity Provider（Casdoor）的 OIDC client 交互。
// 网关作为上游的 OIDC client：浏览器侧跳转其 authorize 端点，回调后后端直连换取 subject。
type UpstreamIDP interface {
	// AuthorizeURL 构造跳转上游 authorize 端点的 URL，携带网关回调地址与关联 state。
	AuthorizeURL(linkedState string) string
	// Exchange 用上游授权码后端直连换取 OIDC subject。
	Exchange(ctx context.Context, code string) (subject string, err error)
}

// stubUpstream 是内置桩上游，用于无真实 Casdoor 的本地联调与契约测试（#11）。
// 真实 OIDC 实现待 #10 部署 Casdoor 后接入。
type stubUpstream struct {
	authorizeURL string
	clientID     string
	callbackURL  string
	scopes       string
}

// NewUpstream 按配置选择上游实现。当前仅支持 stub；oidc 模式待 #10 接入真实 Casdoor。
func NewUpstream(cfg config.OAuthConfig) (UpstreamIDP, error) {
	callbackURL := cfg.GatewayBaseURL + "/oauth/callback/casdoor"
	switch cfg.Upstream.Mode {
	case "stub":
		return &stubUpstream{
			authorizeURL: cfg.Upstream.AuthorizeURL,
			clientID:     cfg.Upstream.ClientID,
			callbackURL:  callbackURL,
			scopes:       cfg.Upstream.Scopes,
		}, nil
	case "oidc":
		return nil, fmt.Errorf("oidc 上游待 #10 部署 Casdoor 后接入")
	default:
		return nil, fmt.Errorf("未知 upstream.mode: %q", cfg.Upstream.Mode)
	}
}

func (s *stubUpstream) AuthorizeURL(linkedState string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.clientID)
	q.Set("redirect_uri", s.callbackURL)
	q.Set("scope", s.scopes)
	q.Set("state", linkedState)
	return s.authorizeURL + "?" + q.Encode()
}

// Exchange 桩实现：把上游授权码直接派生为 subject，便于本地走通流程。
func (s *stubUpstream) Exchange(_ context.Context, code string) (string, error) {
	if code == "" {
		return "", fmt.Errorf("上游授权码为空")
	}
	return "stub-subject:" + code, nil
}
