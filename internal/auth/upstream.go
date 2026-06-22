package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/pysinsjz/vulture-gateway/config"
)

// discoveryTimeout 限制 oidc 模式启动时的 discovery 联网耗时，避免上游不可达时启动无限期挂起。
const discoveryTimeout = 10 * time.Second

// UpstreamIDP 抽象上游 Identity Provider（Casdoor）的 OIDC client 交互。
// 网关作为上游的 OIDC client：浏览器侧跳转其 authorize 端点，回调后后端直连换取 subject。
type UpstreamIDP interface {
	// AuthorizeURL 构造跳转上游 authorize 端点的 URL，携带网关回调地址、关联 state 与 nonce。
	AuthorizeURL(linkedState, nonce string) string
	// Exchange 用上游授权码后端直连换取 OIDC subject；nonce 为发起时签发、用于校验 id_token 防注入/重放。
	Exchange(ctx context.Context, code, nonce string) (subject string, err error)
}

// NewUpstream 按配置选择上游实现。stub 用于本地联调与契约测试；oidc 对接真实 Casdoor（ADR-0012）。
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
		return newOIDCUpstream(cfg.Upstream, callbackURL)
	default:
		return nil, fmt.Errorf("未知 upstream.mode: %q", cfg.Upstream.Mode)
	}
}

// oidcUpstream 是对接真实 Casdoor 的 OIDC client：discovery 取端点、JWKS 验签 id_token、校验 nonce 取 sub。
type oidcUpstream struct {
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// newOIDCUpstream 启动即做 OIDC discovery（issuer → authorize/token/jwks 端点）。
// 上游不可达时在此返回错误，使网关启动快速失败而非带病运行（ADR-0012：启动即 discovery）。
func newOIDCUpstream(up config.UpstreamConfig, callbackURL string) (*oidcUpstream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, up.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery 失败（issuer=%s）: %w", up.Issuer, err)
	}

	return &oidcUpstream{
		oauth2: oauth2.Config{
			ClientID:     up.ClientID,
			ClientSecret: up.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  callbackURL,
			Scopes:       splitScopes(up.Scopes),
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: up.ClientID}),
	}, nil
}

func (u *oidcUpstream) AuthorizeURL(linkedState, nonce string) string {
	return u.oauth2.AuthCodeURL(linkedState, oidc.Nonce(nonce))
}

// Exchange 后端直连换 token（机密客户端，携 client_secret）→ 从 token 取 id_token →
// JWKS 验签 → 校验 nonce 逐字相等 → 返回已验证的 sub。
func (u *oidcUpstream) Exchange(ctx context.Context, code, nonce string) (string, error) {
	if code == "" {
		return "", fmt.Errorf("上游授权码为空")
	}

	token, err := u.oauth2.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("上游 token 交换失败: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", fmt.Errorf("上游 token 响应缺少 id_token")
	}

	idToken, err := u.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("id_token 验签失败: %w", err)
	}

	if idToken.Nonce != nonce {
		return "", fmt.Errorf("id_token nonce 不匹配")
	}

	if idToken.Subject == "" {
		return "", fmt.Errorf("id_token 缺少 sub")
	}
	return idToken.Subject, nil
}

// splitScopes 把空格分隔的 scopes 串切为切片；保证含 openid（OIDC 必需，否则上游不返回 id_token）。
func splitScopes(scopes string) []string {
	fields := strings.Fields(scopes)
	hasOpenID := false
	for _, s := range fields {
		if s == oidc.ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		fields = append([]string{oidc.ScopeOpenID}, fields...)
	}
	return fields
}

// stubUpstream 是内置桩上游，用于无真实 Casdoor 的本地联调与契约测试（#11）。
type stubUpstream struct {
	authorizeURL string
	clientID     string
	callbackURL  string
	scopes       string
}

func (s *stubUpstream) AuthorizeURL(linkedState, nonce string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.clientID)
	q.Set("redirect_uri", s.callbackURL)
	q.Set("scope", s.scopes)
	q.Set("state", linkedState)
	q.Set("nonce", nonce)
	return s.authorizeURL + "?" + q.Encode()
}

// Exchange 桩实现：把上游授权码直接派生为 subject，便于本地走通流程（忽略 nonce）。
func (s *stubUpstream) Exchange(_ context.Context, code, _ string) (string, error) {
	if code == "" {
		return "", fmt.Errorf("上游授权码为空")
	}
	return "stub-subject:" + code, nil
}
