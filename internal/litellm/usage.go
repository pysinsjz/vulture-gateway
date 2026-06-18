package litellm

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Usage 是一次推理的 token 计量（OpenAI usage 形态），计量扣费的输入（#26）。
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// sseChunk 是 SSE 数据 chunk 的部分解析形态：只取计量所需的 delta.content 与末尾 usage。
type sseChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
	Usage *Usage `json:"usage"`
}

// SSESniffer 包装 SSE 写出流：先把字节原样转发到 dst（保证流式完整性），
// 再旁路增量解析事件，记录最终 usage 与累计输出文本字符数（usage 缺失时供估算兜底，#26）。
//
// 增量解析按 "\n\n" 切分完整事件、即时丢弃，内存仅占一个事件 + 尾部残片。
type SSESniffer struct {
	dst             io.Writer
	pending         []byte
	usage           *Usage
	completionChars int
}

// NewSSESniffer 构造嗅探器，写出目标为 dst。
func NewSSESniffer(dst io.Writer) *SSESniffer {
	return &SSESniffer{dst: dst}
}

// Write 先转发到 dst，再旁路解析（解析失败不影响转发）。
func (s *SSESniffer) Write(p []byte) (int, error) {
	n, err := s.dst.Write(p)
	if n > 0 {
		s.consume(p[:n])
	}
	return n, err
}

func (s *SSESniffer) consume(p []byte) {
	s.pending = append(s.pending, p...)
	for {
		idx := bytes.Index(s.pending, []byte("\n\n"))
		if idx < 0 {
			return
		}
		event := s.pending[:idx]
		s.pending = s.pending[idx+2:]
		s.parseEvent(event)
	}
}

func (s *SSESniffer) parseEvent(event []byte) {
	var payload strings.Builder
	for _, line := range strings.Split(string(event), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload.WriteString(strings.TrimSpace(line[len("data:"):]))
	}
	data := payload.String()
	if data == "" || data == "[DONE]" {
		return
	}
	var chunk sseChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return
	}
	for _, ch := range chunk.Choices {
		s.completionChars += len(ch.Delta.Content)
	}
	if chunk.Usage != nil {
		s.usage = chunk.Usage
	}
}

// Usage 返回解析到的最终 usage（无则 nil）。
func (s *SSESniffer) Usage() *Usage { return s.usage }

// CompletionChars 返回累计输出文本字符数（usage 缺失时供估算）。
func (s *SSESniffer) CompletionChars() int { return s.completionChars }

// jsonResp 是非流式响应体的部分解析形态。
type jsonResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage *Usage `json:"usage"`
}

// UsageFromJSON 解析非流式响应体的 usage 与输出文本字符数（usage 缺失返回 nil + 字符数供估算）。
func UsageFromJSON(body []byte) (*Usage, int) {
	var resp jsonResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0
	}
	chars := 0
	for _, ch := range resp.Choices {
		chars += len(ch.Message.Content)
	}
	return resp.Usage, chars
}
