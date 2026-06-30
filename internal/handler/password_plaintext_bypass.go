package handler

import "github.com/pysinsjz/vulture-gateway/internal/auth"

// resolveSubmittedPassword 选用 encrypted（前端加密路径）或 dev/test 旁路下用 plain 现场
// 公钥加密后返回密文，供下游 service/signin 走原 RSA 解密路径，下游零感知。
// 第二返回值是面向用户的错误提示（已映射、非空即应回渲带提示，CSRF 等会话状态由调用方负责重置）。
//
// 仅当 AuthConfig.AllowPlaintextPassword=true 时接受 plain；prod/staging 由 config.validate
// 顶为 false，handler 在此处显式拒绝并提示用户改走 https:// 或 http://localhost。
//   - encrypted 非空：原样返回（前端在安全上下文内拿得到 WebCrypto，正常加密路径）。
//   - encrypted 空 + plain 非空 + 旁路允许：用网关公钥加密 plain → 返回密文。
//   - encrypted 空 + plain 非空 + 旁路不允许：返回明确提示。
//   - encrypted 空 + plain 空：空字符串透传，由下游业务校验（如密码策略 / 凭据缺失）拦截。
func resolveSubmittedPassword(rsa *auth.RSADecryptor, allowPlaintext bool, encrypted, plain string) (string, string) {
	if encrypted != "" {
		return encrypted, ""
	}
	if plain == "" {
		return "", ""
	}
	if !allowPlaintext {
		return "", "当前网关未开启明文密码调试旁路，请通过 https:// 或 http://localhost 重新打开此页。"
	}
	ct, err := rsa.EncryptPlaintext(plain)
	if err != nil {
		return "", "明文密码处理失败，请稍后重试。"
	}
	return ct, ""
}
