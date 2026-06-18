package litellm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// ErrIdleTimeout 表示流式透传中 chunk 间空闲超过 idle 上限被中断（#24 / ADR-0008）。
var ErrIdleTimeout = errors.New("litellm: 流式空闲超时")

// InjectIncludeUsage 在流式请求体中强制注入 stream_options.include_usage=true（#24）。
//
// 返回 (新体, 是否流式, error)：
//   - stream==true：合并/覆盖 stream_options.include_usage=true，保留其余所有字段原样透传。
//   - stream 非 true（含缺省）：不改动 stream_options 并返回 isStream=false——
//     因 OpenAI/litellm 对非流式请求携带 stream_options 会返回 400，故非流式绝不注入。
//   - 体非法 JSON：返回原 body + error，调用方应原样转发，让 litellm 返标准 400。
//
// 实现用 map[string]any 解析以无损保留未知字段（薄代理）；代价是 key 顺序与数字表示被 JSON 归一化，
// 对 OpenAI 兼容请求无语义影响。
func InjectIncludeUsage(body []byte) ([]byte, bool, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body, false, err
	}
	stream, _ := m["stream"].(bool)
	if !stream {
		return body, false, nil
	}

	opts, ok := m["stream_options"].(map[string]any)
	if !ok {
		opts = map[string]any{}
	}
	opts["include_usage"] = true
	m["stream_options"] = opts

	out, err := json.Marshal(m)
	if err != nil {
		return body, true, err
	}
	return out, true, nil
}

// PumpStream 将上游 SSE 流逐 chunk 透传到 dst，并按双超时治理连接（#24 / ADR-0008）：
//   - 空闲超时：相邻 chunk 间隔超过 idle → 返回 ErrIdleTimeout。
//   - 总时长超时：由调用方在 ctx 上设 deadline，触发 → 返回 ctx.Err()（DeadlineExceeded）。
//
// 每写出一个 chunk 调用 flush（可为 nil）以即时下推给桌面端。EOF 正常收尾返回 nil。
// 读取在独立 goroutine 中进行，超时/取消时本函数即返回；调用方负责关闭 src 以解除阻塞读。
func PumpStream(ctx context.Context, dst io.Writer, flush func(), src io.Reader, idle time.Duration) error {
	type chunk struct {
		data []byte
		err  error
	}
	ch := make(chan chunk, 1)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				select {
				case ch <- chunk{data: b}:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				select {
				case ch <- chunk{err: err}:
				case <-ctx.Done():
				}
				return
			}
		}
	}()

	idleTimer := time.NewTimer(idle)
	defer idleTimer.Stop()

	for {
		select {
		case c := <-ch:
			if c.err != nil {
				if errors.Is(c.err, io.EOF) {
					return nil
				}
				return c.err
			}
			if _, err := dst.Write(c.data); err != nil {
				return err
			}
			if flush != nil {
				flush()
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idle)
		case <-idleTimer.C:
			return ErrIdleTimeout
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
