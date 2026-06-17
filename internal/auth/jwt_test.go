package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/pysinsjz/vulture-gateway/config"
)

func testSigner() *Signer {
	return NewSigner(config.JWTConfig{
		Secret:    "unit-test-secret",
		Issuer:    "vulture-gateway",
		AccessTTL: 30 * time.Minute,
	})
}

func TestSigner_IssueVerify_RoundTrip(t *testing.T) {
	s := testSigner()
	token, err := s.Issue("user-1", "dev-1", 7)
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}

	claims, err := s.Verify(token)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("sub = %q, 期望 user-1", claims.Subject)
	}
	if claims.DeviceID != "dev-1" {
		t.Errorf("device_id = %q, 期望 dev-1", claims.DeviceID)
	}
	if claims.TokenVersion != 7 {
		t.Errorf("token_version = %d, 期望 7", claims.TokenVersion)
	}
}

func TestSigner_Verify_Rejects(t *testing.T) {
	s := testSigner()

	expired, err := s.issueAt("user-1", "dev-1", 1, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("构造过期 token 失败: %v", err)
	}

	other := NewSigner(config.JWTConfig{Secret: "different-secret", Issuer: "vulture-gateway", AccessTTL: 30 * time.Minute})
	badSig, err := other.Issue("user-1", "dev-1", 1)
	if err != nil {
		t.Fatalf("构造异签 token 失败: %v", err)
	}

	wrongIssuer := NewSigner(config.JWTConfig{Secret: "unit-test-secret", Issuer: "someone-else", AccessTTL: 30 * time.Minute})
	badIssuer, err := wrongIssuer.Issue("user-1", "dev-1", 1)
	if err != nil {
		t.Fatalf("构造异 issuer token 失败: %v", err)
	}

	cases := map[string]string{
		"空串":        "",
		"垃圾串":       "not-a-jwt",
		"过期":        expired,
		"签名不匹配":     badSig,
		"issuer 不符": badIssuer,
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Verify(token); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Verify 应返回 ErrInvalidToken, 实际 %v", err)
			}
		})
	}
}
