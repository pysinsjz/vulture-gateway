package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"合规-字母数字", "abcd1234", nil},
		{"合规-含符号仍需字母数字", "ab!2cd34", nil},
		{"合规-边界8", "abcdefg1", nil},
		{"合规-边界64", strings.Repeat("a", 60) + "1234", nil},
		{"太短-7", "abcdef1", ErrPasswordTooShort},
		{"太长-65", strings.Repeat("a", 61) + "1234", ErrPasswordTooLong},
		{"缺数字", "abcdefgh", ErrPasswordMissingKind},
		{"缺字母", "12345678", ErrPasswordMissingKind},
		{"空", "", ErrPasswordTooShort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePassword(c.input)
			if !errors.Is(err, c.wantErr) {
				t.Errorf("ValidatePassword(%q) = %v, 期望 %v", c.input, err, c.wantErr)
			}
		})
	}
}
