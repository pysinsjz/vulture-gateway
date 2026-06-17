package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyS256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !VerifyS256(verifier, challenge) {
		t.Error("正确的 verifier/challenge 应通过")
	}
	if VerifyS256("wrong", challenge) {
		t.Error("错误 verifier 应不通过")
	}
	if VerifyS256(verifier, "wrong-challenge") {
		t.Error("错误 challenge 应不通过")
	}
	if VerifyS256("", challenge) || VerifyS256(verifier, "") {
		t.Error("空值应不通过")
	}
}
