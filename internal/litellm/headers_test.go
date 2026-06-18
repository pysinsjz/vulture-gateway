package litellm_test

import (
	"net/http"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

func TestCopySafeHeaders(t *testing.T) {
	src := http.Header{}
	// 成本敏感头（应剥除）。
	src.Set("X-Litellm-Response-Cost", "0.0012")
	src.Set("X-Litellm-Key-Spend", "1.5")
	src.Set("X-Litellm-Model-Api-Base", "https://api.openai.com")
	src.Set("llm_provider-region", "us-east")
	// 逐跳头（应剥除）。
	src.Set("Content-Length", "123")
	src.Set("Connection", "keep-alive")
	// 应保留。
	src.Set("X-Litellm-Call-Id", "call-abc")
	src.Set("Content-Type", "application/json")

	dst := http.Header{}
	litellm.CopySafeHeaders(dst, src)

	stripped := []string{"X-Litellm-Response-Cost", "X-Litellm-Key-Spend", "X-Litellm-Model-Api-Base", "llm_provider-region", "Content-Length", "Connection"}
	for _, h := range stripped {
		if dst.Get(h) != "" {
			t.Errorf("头 %q 应被剥除, 实际 %q", h, dst.Get(h))
		}
	}
	if dst.Get("X-Litellm-Call-Id") != "call-abc" {
		t.Errorf("x-litellm-call-id 应保留, 实际 %q", dst.Get("X-Litellm-Call-Id"))
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type 应保留, 实际 %q", dst.Get("Content-Type"))
	}
}
