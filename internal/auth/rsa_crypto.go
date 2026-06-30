package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// RSADecryptor 持有服务端 RSA 私钥，解密前端用配对公钥 RSA-OAEP(SHA-256) 加密的密码（ADR-0013）。
// 边界：防窃听不防 MITM，仅测试期过渡 + 纵深防御，非 HTTPS 替代品。
type RSADecryptor struct {
	priv      *rsa.PrivateKey
	publicPEM string
}

// NewRSADecryptor 从 PEM 私钥（PKCS#8 优先，回退 PKCS#1）构造解密器，并预生成 SPKI 公钥 PEM 供下发。
func NewRSADecryptor(privPEM string) (*RSADecryptor, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("RSA 私钥 PEM 解析失败：非有效 PEM 块")
	}

	priv, err := parseRSAPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("序列化 RSA 公钥失败: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return &RSADecryptor{priv: priv, publicPEM: string(pubPEM)}, nil
}

// parseRSAPrivateKey 兼容 PKCS#8 与 PKCS#1 两种 DER 编码。
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("私钥非 RSA 类型: %T", key)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("解析 RSA 私钥失败（PKCS#8/PKCS#1 均不匹配）: %w", err)
	}
	return key, nil
}

// PublicKeyPEM 返回 SPKI 格式公钥 PEM，供登录页下发给前端做 RSA-OAEP 加密。
func (d *RSADecryptor) PublicKeyPEM() string {
	return d.publicPEM
}

// Decrypt 解密 base64 编码的 RSA-OAEP(SHA-256) 密文，返回明文。
func (d *RSADecryptor) Decrypt(b64Ciphertext string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return "", fmt.Errorf("密文 base64 解码失败: %w", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, d.priv, ct, nil)
	if err != nil {
		return "", fmt.Errorf("RSA-OAEP 解密失败: %w", err)
	}
	return string(plain), nil
}

// EncryptPlaintext 用网关持有的公钥做 RSA-OAEP(SHA-256) 加密，返回 base64 密文。
// 仅供 dev/test 明文密码旁路使用（AuthConfig.AllowPlaintextPassword）：浏览器非安全上下文
// 拿不到 WebCrypto 时，handler 用此方法把 plain_password 重新加密一遍再喂给 service，
// 避免修改 service/auth 域既有 RSA 解密路径。prod/staging 禁用此旁路（启动校验顶住）。
func (d *RSADecryptor) EncryptPlaintext(plain string) (string, error) {
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &d.priv.PublicKey, []byte(plain), nil)
	if err != nil {
		return "", fmt.Errorf("RSA-OAEP 加密失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}
