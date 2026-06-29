package auth

import (
	"errors"
	"unicode"
	"unicode/utf8"
)

// 密码策略边界（ADR-0015）：凭据创建入口较登录基线更严——最小 8 / 最大 64 字符，
// 且必须同时含字母与数字。长度按 Unicode 字符（rune）计，非字节。
const (
	PasswordMinLen = 8
	PasswordMaxLen = 64
)

// 密码策略校验错误（哨兵值），供上层映射为用户可见提示。
var (
	ErrPasswordTooShort    = errors.New("密码长度不足")
	ErrPasswordTooLong     = errors.New("密码长度超限")
	ErrPasswordMissingKind = errors.New("密码须同时包含字母与数字")
)

// ValidatePassword 校验明文密码是否满足策略：8–64 字符且同时含字母与数字。
// 返回具体哨兵错误以便上层给出精确提示；合规返回 nil。
func ValidatePassword(plain string) error {
	n := utf8.RuneCountInString(plain)
	if n < PasswordMinLen {
		return ErrPasswordTooShort
	}
	if n > PasswordMaxLen {
		return ErrPasswordTooLong
	}
	var hasLetter, hasDigit bool
	for _, r := range plain {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return ErrPasswordMissingKind
	}
	return nil
}
