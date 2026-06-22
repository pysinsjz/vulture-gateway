package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/pysinsjz/vulture-gateway/config"
)

// ---------- stub 上游 ----------

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

	// oidc 模式对不可达 issuer 应在 discovery 阶段快速失败（启动即 discovery）。
	oidc := stubCfg()
	oidc.Upstream.Mode = "oidc"
	oidc.Upstream.Issuer = "http://127.0.0.1:1/不可达"
	if _, err := NewUpstream(oidc); err == nil {
		t.Error("oidc 模式对不可达 issuer 应返回 discovery 失败")
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
	raw := up.AuthorizeURL("st_link123", "nonce_abc")
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
	if q.Get("nonce") != "nonce_abc" {
		t.Errorf("应携带 nonce, 实际 %q", q.Get("nonce"))
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
	sub, err := up.Exchange(context.Background(), "CODE1", "nonce_ignored")
	if err != nil {
		t.Fatalf("Exchange 失败: %v", err)
	}
	if sub != "stub-subject:CODE1" {
		t.Errorf("subject 不符: %q", sub)
	}
	if _, err := up.Exchange(context.Background(), "", "n"); err == nil {
		t.Error("空 code 应报错")
	}
}

// ---------- oidc 上游（httptest 假 provider） ----------

const (
	testClientID = "test-gateway-client"
	testKID      = "test-key-1"
	testSubject  = "casdoor-user-guid-001"
)

// mockIDP 是一个最小 OIDC provider：提供 discovery、JWKS、token 端点，token 端点返回测试现签的 id_token。
type mockIDP struct {
	server  *httptest.Server
	key     *rsa.PrivateKey
	issuer  string
	idToken string // 下次 /token 返回的 id_token（各用例自行设置）
	noIDTok bool   // 为 true 时 /token 不返回 id_token
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	m := &mockIDP{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 m.issuer,
			"authorization_endpoint": m.issuer + "/login/oauth/authorize",
			"token_endpoint":         m.issuer + "/token",
			"jwks_uri":               m.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jwksFor(&key.PublicKey, testKID))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600}
		if !m.noIDTok {
			resp["id_token"] = m.idToken
		}
		writeJSON(w, resp)
	})

	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

// idTokenClaims 控制现签 id_token 的关键字段，便于构造各失败分支。
type idTokenClaims struct {
	iss   string
	aud   string
	sub   string
	nonce string
	exp   time.Time
	kid   string
}

func (m *mockIDP) mint(t *testing.T, c idTokenClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   c.iss,
		"aud":   c.aud,
		"sub":   c.sub,
		"nonce": c.nonce,
		"iat":   time.Now().Unix(),
		"exp":   c.exp.Unix(),
	})
	tok.Header["kid"] = c.kid
	signed, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("签发 id_token 失败: %v", err)
	}
	return signed
}

// validClaims 返回一份默认有效的 claims，用例可按需改单字段。
func (m *mockIDP) validClaims(nonce string) idTokenClaims {
	return idTokenClaims{
		iss:   m.issuer,
		aud:   testClientID,
		sub:   testSubject,
		nonce: nonce,
		exp:   time.Now().Add(time.Hour),
		kid:   testKID,
	}
}

func (m *mockIDP) newUpstream(t *testing.T) UpstreamIDP {
	t.Helper()
	up, err := NewUpstream(config.OAuthConfig{
		GatewayBaseURL: "http://127.0.0.1:8080",
		Upstream: config.UpstreamConfig{
			Mode:         "oidc",
			Issuer:       m.issuer,
			ClientID:     testClientID,
			ClientSecret: "test-secret",
			Scopes:       "openid profile",
		},
	})
	if err != nil {
		t.Fatalf("装配 oidc 上游失败: %v", err)
	}
	return up
}

func TestOIDCUpstream_AuthorizeURL(t *testing.T) {
	m := newMockIDP(t)
	up := m.newUpstream(t)

	raw := up.AuthorizeURL("st_link", "nonce_xyz")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthorizeURL 非法: %v", err)
	}
	if !strings.HasPrefix(raw, m.issuer+"/login/oauth/authorize?") {
		t.Errorf("应基于 discovery 的 authorize 端点, 实际 %s", raw)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type": "code",
		"client_id":     testClientID,
		"state":         "st_link",
		"nonce":         "nonce_xyz",
		"redirect_uri":  "http://127.0.0.1:8080/oauth/callback/casdoor",
	}
	for k, want := range checks {
		if q.Get(k) != want {
			t.Errorf("authorize 参数 %s=%q, 期望 %q", k, q.Get(k), want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope 应含 openid, 实际 %q", q.Get("scope"))
	}
}

func TestOIDCUpstream_Exchange_Success(t *testing.T) {
	m := newMockIDP(t)
	up := m.newUpstream(t)

	m.idToken = m.mint(t, m.validClaims("nonce_ok"))
	sub, err := up.Exchange(context.Background(), "auth_code", "nonce_ok")
	if err != nil {
		t.Fatalf("Exchange 应成功: %v", err)
	}
	if sub != testSubject {
		t.Errorf("subject=%q, 期望 %q", sub, testSubject)
	}
}

func TestOIDCUpstream_Exchange_Failures(t *testing.T) {
	m := newMockIDP(t)
	up := m.newUpstream(t)

	cases := []struct {
		name   string
		nonce  string // 传给 Exchange 的期望 nonce
		mutate func(c *idTokenClaims)
		noTok  bool
	}{
		{name: "nonce 不匹配", nonce: "expected", mutate: func(c *idTokenClaims) { c.nonce = "tampered" }},
		{name: "iss 不符", nonce: "n", mutate: func(c *idTokenClaims) { c.iss = "https://evil.example" }},
		{name: "aud 不符", nonce: "n", mutate: func(c *idTokenClaims) { c.aud = "other-client" }},
		{name: "已过期", nonce: "n", mutate: func(c *idTokenClaims) { c.exp = time.Now().Add(-time.Hour) }},
		{name: "未知 kid（验签失败）", nonce: "n", mutate: func(c *idTokenClaims) { c.kid = "unknown-kid" }},
		{name: "缺少 id_token", nonce: "n", noTok: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m.noIDTok = tc.noTok
			defer func() { m.noIDTok = false }()
			if !tc.noTok {
				claims := m.validClaims(tc.nonce)
				tc.mutate(&claims)
				m.idToken = m.mint(t, claims)
			}
			if _, err := up.Exchange(context.Background(), "code", tc.nonce); err == nil {
				t.Errorf("%s: 应返回错误", tc.name)
			}
		})
	}

	if _, err := up.Exchange(context.Background(), "", "n"); err == nil {
		t.Error("空 code 应报错")
	}
}

// ---------- 测试辅助 ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// jwksFor 用 RSA 公钥构造单密钥 JWKS。
func jwksFor(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
}
