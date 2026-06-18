package litellm_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

// stream:true 且无 stream_options：强制注入 include_usage=true，其余字段原样保留。
func TestInjectIncludeUsage_StreamInjects(t *testing.T) {
	in := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true,"temperature":0.7}`)
	out, isStream, err := litellm.InjectIncludeUsage(in)
	if err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	if !isStream {
		t.Fatal("应识别为流式")
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("输出非法 JSON: %v", err)
	}
	so, ok := m["stream_options"].(map[string]any)
	if !ok || so["include_usage"] != true {
		t.Errorf("应注入 stream_options.include_usage=true, 实际 %v", m["stream_options"])
	}
	// 透传字段保留。
	if m["model"] != "gpt-4" || m["temperature"] != 0.7 {
		t.Errorf("透传字段丢失: %v", m)
	}
}

// stream:true 且已有 stream_options：保留既有键，仅补/覆盖 include_usage。
func TestInjectIncludeUsage_MergesExistingStreamOptions(t *testing.T) {
	in := []byte(`{"model":"x","stream":true,"stream_options":{"continuous_usage_stats":true}}`)
	out, _, err := litellm.InjectIncludeUsage(in)
	if err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	so := m["stream_options"].(map[string]any)
	if so["include_usage"] != true || so["continuous_usage_stats"] != true {
		t.Errorf("应合并既有 stream_options, 实际 %v", so)
	}
}

// stream:false：不得注入 stream_options（OpenAI 对非流式带该字段会 400）。
func TestInjectIncludeUsage_NonStreamUntouched(t *testing.T) {
	in := []byte(`{"model":"x","stream":false}`)
	out, isStream, err := litellm.InjectIncludeUsage(in)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if isStream {
		t.Fatal("stream:false 不应识别为流式")
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if _, has := m["stream_options"]; has {
		t.Error("非流式不应注入 stream_options")
	}
}

// 缺省 stream 字段视为非流式，不注入。
func TestInjectIncludeUsage_AbsentStreamUntouched(t *testing.T) {
	in := []byte(`{"model":"x"}`)
	_, isStream, err := litellm.InjectIncludeUsage(in)
	if err != nil || isStream {
		t.Fatalf("缺省 stream 应视为非流式且无错, isStream=%v err=%v", isStream, err)
	}
}

// 非法 JSON：返回错误并回吐原 body，由调用方原样转发让 litellm 返标准 400。
func TestInjectIncludeUsage_InvalidJSON(t *testing.T) {
	in := []byte(`not json`)
	out, _, err := litellm.InjectIncludeUsage(in)
	if err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
	if string(out) != string(in) {
		t.Errorf("出错时应回吐原 body, 实际 %q", out)
	}
}

// 正路：逐 chunk 透传到 dst 并 flush，EOF 正常收尾返回 nil。
func TestPumpStream_PassesThroughAndFlushes(t *testing.T) {
	pr, pw := io.Pipe()
	var dst strings.Builder
	var flushes int

	go func() {
		_, _ = io.WriteString(pw, "data: a\n\n")
		_, _ = io.WriteString(pw, "data: b\n\n")
		_, _ = io.WriteString(pw, "data: [DONE]\n\n")
		_ = pw.Close()
	}()

	err := litellm.PumpStream(context.Background(), &dst, func() { flushes++ }, pr, time.Second)
	if err != nil {
		t.Fatalf("正路应返回 nil, 实际 %v", err)
	}
	got := dst.String()
	for _, want := range []string{"data: a", "data: b", "[DONE]"} {
		if !strings.Contains(got, want) {
			t.Errorf("输出缺 %q: %q", want, got)
		}
	}
	if flushes == 0 {
		t.Error("应至少 flush 一次")
	}
}

// 空闲超时：首 chunk 后停顿超过 idle → 返回 ErrIdleTimeout。
func TestPumpStream_IdleTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	var dst strings.Builder

	go func() {
		_, _ = io.WriteString(pw, "data: a\n\n")
		// 之后长时间不写，触发空闲超时；保持 writer 不关闭。
		time.Sleep(500 * time.Millisecond)
		_ = pw.Close()
	}()

	err := litellm.PumpStream(context.Background(), &dst, nil, pr, 50*time.Millisecond)
	if !errors.Is(err, litellm.ErrIdleTimeout) {
		t.Fatalf("应空闲超时, 实际 %v", err)
	}
}

// 空闲边界：每次写间隔略小于 idle → 不中断，正常收尾。
func TestPumpStream_IdleNotTrippedWhenActive(t *testing.T) {
	pr, pw := io.Pipe()
	var dst strings.Builder

	go func() {
		for i := 0; i < 4; i++ {
			_, _ = io.WriteString(pw, "data: x\n\n")
			time.Sleep(20 * time.Millisecond) // < 60ms idle
		}
		_ = pw.Close()
	}()

	err := litellm.PumpStream(context.Background(), &dst, nil, pr, 60*time.Millisecond)
	if err != nil {
		t.Fatalf("活跃流不应空闲超时, 实际 %v", err)
	}
}

// 总时长超时：ctx 截止（即使流持续活跃）→ 返回 ctx.DeadlineExceeded。
func TestPumpStream_TotalTimeoutViaContext(t *testing.T) {
	pr, pw := io.Pipe()
	var dst strings.Builder

	go func() {
		for {
			if _, err := io.WriteString(pw, "data: x\n\n"); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	defer pw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	err := litellm.PumpStream(ctx, &dst, nil, pr, time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("应总时长超时, 实际 %v", err)
	}
}
