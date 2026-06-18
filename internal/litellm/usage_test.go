package litellm_test

import (
	"strings"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

// SSESniffer：原样转发字节，且解析出末尾 usage 与累计输出字符数。
func TestSSESniffer_ForwardsAndCapturesUsage(t *testing.T) {
	var out strings.Builder
	s := litellm.NewSSESniffer(&out)

	chunks := []string{
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":3,\"total_tokens\":15}}\n\n",
		"data: [DONE]\n\n",
	}
	for _, c := range chunks {
		if _, err := s.Write([]byte(c)); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
	}

	if out.String() != strings.Join(chunks, "") {
		t.Errorf("字节应原样转发, 实际 %q", out.String())
	}
	u := s.Usage()
	if u == nil || u.TotalTokens != 15 || u.PromptTokens != 12 || u.CompletionTokens != 3 {
		t.Fatalf("usage 解析错误: %+v", u)
	}
	if s.CompletionChars() != len("Hello") {
		t.Errorf("输出字符数 = %d, 期望 %d", s.CompletionChars(), len("Hello"))
	}
}

// SSESniffer：跨 Write 边界切分的事件也能正确解析。
func TestSSESniffer_SplitAcrossWrites(t *testing.T) {
	var out strings.Builder
	s := litellm.NewSSESniffer(&out)
	_, _ = s.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_to"))
	_, _ = s.Write([]byte("kens\":2,\"total_tokens\":3}}\n\n"))
	if u := s.Usage(); u == nil || u.TotalTokens != 3 {
		t.Fatalf("跨 Write 事件应解析, 实际 %+v", u)
	}
}

// SSESniffer：无 usage chunk 时 Usage()=nil，但累计输出字符数仍可用于估算。
func TestSSESniffer_NoUsageStillCountsChars(t *testing.T) {
	var out strings.Builder
	s := litellm.NewSSESniffer(&out)
	_, _ = s.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"abcd\"}}]}\n\n"))
	_, _ = s.Write([]byte("data: [DONE]\n\n"))
	if s.Usage() != nil {
		t.Error("无 usage chunk 应返回 nil")
	}
	if s.CompletionChars() != 4 {
		t.Errorf("输出字符数 = %d, 期望 4", s.CompletionChars())
	}
}

// UsageFromJSON：非流式响应体解析 usage 与输出字符数。
func TestUsageFromJSON(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"content":"hello"}}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)
	u, chars := litellm.UsageFromJSON(body)
	if u == nil || u.TotalTokens != 7 {
		t.Fatalf("usage 解析错误: %+v", u)
	}
	if chars != 5 {
		t.Errorf("输出字符数 = %d, 期望 5", chars)
	}

	// 缺 usage：返回 nil + 字符数。
	u2, chars2 := litellm.UsageFromJSON([]byte(`{"choices":[{"message":{"content":"hi"}}]}`))
	if u2 != nil || chars2 != 2 {
		t.Errorf("缺 usage 应 nil + chars=2, 实际 %+v / %d", u2, chars2)
	}
}
