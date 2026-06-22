package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// genTestKeyPEM 生成一对 RSA 密钥，返回 PKCS#8 私钥 PEM 与原始公钥（供测试加密）。
func genTestKeyPEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(privPEM), &key.PublicKey
}

// encryptOAEP 用公钥 RSA-OAEP(SHA-256) 加密并 base64，模拟前端提交的密文。
func encryptOAEP(t *testing.T, pub *rsa.PublicKey, plain string) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(plain), nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func TestRSADecryptor_RoundTrip(t *testing.T) {
	privPEM, pub := genTestKeyPEM(t)
	dec, err := NewRSADecryptor(privPEM)
	if err != nil {
		t.Fatalf("构造解密器失败: %v", err)
	}

	for _, plain := range []string{"s3cr3t-pass", "密码😀", ""} {
		ct := encryptOAEP(t, pub, plain)
		got, err := dec.Decrypt(ct)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
		if got != plain {
			t.Errorf("解密结果 = %q, 期望 %q", got, plain)
		}
	}
}

// PublicKeyPEM 下发的公钥应可被标准库解析回 RSA 公钥，且用它加密能被私钥解开（前端拿到的就是它）。
func TestRSADecryptor_PublicKeyPEMUsable(t *testing.T) {
	privPEM, _ := genTestKeyPEM(t)
	dec, err := NewRSADecryptor(privPEM)
	if err != nil {
		t.Fatalf("构造解密器失败: %v", err)
	}

	block, _ := pem.Decode([]byte(dec.PublicKeyPEM()))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("PublicKeyPEM 非 SPKI PUBLIC KEY 块: %+v", block)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析公钥失败: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("公钥非 RSA 类型: %T", pubAny)
	}

	ct := encryptOAEP(t, pub, "from-frontend")
	got, err := dec.Decrypt(ct)
	if err != nil || got != "from-frontend" {
		t.Errorf("用下发公钥加密应能解开: got=%q err=%v", got, err)
	}
}

func TestRSADecryptor_DecryptErrors(t *testing.T) {
	privPEM, pub := genTestKeyPEM(t)
	dec, _ := NewRSADecryptor(privPEM)

	t.Run("非法 base64", func(t *testing.T) {
		if _, err := dec.Decrypt("@@@not-base64@@@"); err == nil {
			t.Error("非法 base64 应返回错误")
		}
	})

	t.Run("错误密文", func(t *testing.T) {
		bad := base64.StdEncoding.EncodeToString([]byte("garbage-not-a-valid-rsa-block"))
		if _, err := dec.Decrypt(bad); err == nil {
			t.Error("错误密文应返回错误")
		}
	})

	t.Run("异钥加密的密文", func(t *testing.T) {
		_, otherPub := genTestKeyPEM(t)
		ct := encryptOAEP(t, otherPub, "x")
		_ = pub
		if _, err := dec.Decrypt(ct); err == nil {
			t.Error("异钥密文应解密失败")
		}
	})
}

func TestNewRSADecryptor_InvalidPEM(t *testing.T) {
	for _, bad := range []string{"", "not pem", "-----BEGIN PRIVATE KEY-----\nbm90LWtleQ==\n-----END PRIVATE KEY-----"} {
		if _, err := NewRSADecryptor(bad); err == nil {
			t.Errorf("非法 PEM %q 应返回错误", bad)
		}
	}
}
