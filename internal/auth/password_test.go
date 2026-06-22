package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher_HashThenCompare(t *testing.T) {
	h := NewBcryptHasher(bcrypt.DefaultCost)

	cases := []struct {
		name  string
		plain string
		wrong string // 在 bcrypt 72 字节有效区内与 plain 不同的错误密码
	}{
		{"普通密码", "s3cr3t-pass", "s3cr3t-Pass"},
		{"含 Unicode", "密码pass😀", "密码pass🙂"},
		{"空串", "", "x"},
		{"恰好72字节", strings.Repeat("a", 72), strings.Repeat("a", 71) + "b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hash, err := h.Hash(c.plain)
			if err != nil {
				t.Fatalf("Hash 失败: %v", err)
			}
			if hash == c.plain {
				t.Error("hash 不应等于明文")
			}
			if !h.Compare(hash, c.plain) {
				t.Error("同明文 Compare 应为 true")
			}
			if h.Compare(hash, c.wrong) {
				t.Error("不同明文 Compare 应为 false")
			}
		})
	}
}

func TestBcryptHasher_CostIs12(t *testing.T) {
	h := NewBcryptHasher(12)
	hash, err := h.Hash("whatever")
	if err != nil {
		t.Fatalf("Hash 失败: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("解析 cost 失败: %v", err)
	}
	if cost != 12 {
		t.Errorf("cost = %d, 期望 12", cost)
	}
}

func TestBcryptHasher_InvalidCostFallsBackTo12(t *testing.T) {
	for _, bad := range []int{0, 3, 40} { // <MinCost 或 >MaxCost
		h := NewBcryptHasher(bad)
		hash, err := h.Hash("x")
		if err != nil {
			t.Fatalf("Hash 失败: %v", err)
		}
		if cost, _ := bcrypt.Cost([]byte(hash)); cost != 12 {
			t.Errorf("非法 cost=%d 应回落 12, 实际 %d", bad, cost)
		}
	}
}

func TestBcryptHasher_CompareInvalidHash(t *testing.T) {
	h := NewBcryptHasher(12)
	// 非法 hash 不应 panic，返回 false。
	if h.Compare("not-a-bcrypt-hash", "x") {
		t.Error("非法 hash Compare 应为 false")
	}
	if h.Compare("", "x") {
		t.Error("空 hash Compare 应为 false")
	}
}

func TestBcryptHasher_TooLongPassword(t *testing.T) {
	h := NewBcryptHasher(12)
	// bcrypt 上限 72 字节，超长应返回错误而非静默截断。
	if _, err := h.Hash(strings.Repeat("a", 73)); err == nil {
		t.Error("超 72 字节密码应返回错误")
	}
}
