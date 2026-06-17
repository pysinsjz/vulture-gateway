package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyS256 校验 PKCE：challenge 应等于 base64url(sha256(verifier))（无填充，RFC 7636）。
// 用常量时间比较避免时序侧信道。
func VerifyS256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}
