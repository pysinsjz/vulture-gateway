// Package idgen 生成带前缀的加密随机标识符（User UUID、GW_CODE、关联 state 等）。
package idgen

import (
	"crypto/rand"
	"encoding/base64"
)

// New 返回形如 "<prefix>_<22 字符 base64url 随机>" 的标识符。
func New(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 在受支持平台上不会失败；万一失败则 panic，宁可崩溃也不签发弱随机标识。
		panic("idgen: 读取随机源失败: " + err.Error())
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}
