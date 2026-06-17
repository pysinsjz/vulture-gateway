// Package auth 负责 access JWT 的签发/校验，以及即时吊销所依赖的 token_version 存储。
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/pysinsjz/vulture-gateway/config"
)

// ErrInvalidToken 表示 token 缺失签名校验、过期、或结构非法等任意校验失败。
// #9 切片下所有校验失败统一映射为 401（见中间件）。
var ErrInvalidToken = errors.New("invalid access token")

// AccessClaims 是 access JWT 的载荷。
// sub（用户 ID）走 RegisteredClaims.Subject；device_id + token_version 为自定义 claim。
type AccessClaims struct {
	DeviceID     string `json:"device_id"`
	TokenVersion int64  `json:"token_version"`
	jwt.RegisteredClaims
}

// Signer 用 HS256 对称密钥签发/校验 access JWT。
type Signer struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// NewSigner 按配置构造签发器。
func NewSigner(cfg config.JWTConfig) *Signer {
	return &Signer{
		secret: []byte(cfg.Secret),
		issuer: cfg.Issuer,
		ttl:    cfg.AccessTTL,
	}
}

// TTL 暴露 access JWT 寿命，供 OAuth token 响应的 expires_in 使用。
func (s *Signer) TTL() time.Duration { return s.ttl }

// Issue 以当前时间为基准签发一枚 access JWT。
func (s *Signer) Issue(sub, deviceID string, tokenVersion int64) (string, error) {
	return s.issueAt(sub, deviceID, tokenVersion, time.Now())
}

// issueAt 以指定时间为基准签发，便于测试构造过期/未来 token。
func (s *Signer) issueAt(sub, deviceID string, tokenVersion int64, now time.Time) (string, error) {
	claims := AccessClaims{
		DeviceID:     deviceID,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("签发 access JWT 失败: %w", err)
	}
	return signed, nil
}

// Verify 校验签名、签名算法与有效期，返回解析出的 claims。任意失败均返回 ErrInvalidToken。
func (s *Signer) Verify(tokenString string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("非预期的签名算法: %v", t.Header["alg"])
		}
		return s.secret, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, ErrInvalidToken
	}
	if claims.DeviceID == "" || claims.Subject == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
