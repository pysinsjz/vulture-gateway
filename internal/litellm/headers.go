package litellm

import (
	"net/http"
	"strings"
)

// costSensitiveHeaders 是必须从上游响应剥除的成本敏感头（精确名，大小写不敏感，§1 / #23）。
// x-litellm-call-id 不在此列——它用于请求追踪，需保留透传。
var costSensitiveHeaders = map[string]struct{}{
	"x-litellm-response-cost":   {},
	"x-litellm-key-spend":       {},
	"x-litellm-model-api-base":  {},
	"x-litellm-key-max-budget":  {},
	"x-litellm-key-budget-used": {},
}

// costSensitivePrefixes 是按前缀剥除的成本敏感头族（如 llm_provider-*）。
var costSensitivePrefixes = []string{"llm_provider-"}

// hopByHopHeaders 是逐跳头，不应透传给桌面端；Content-Length 由 Go 写体时重算。
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-length":      {},
}

// CopySafeHeaders 把上游响应头复制到 dst，剥除成本敏感头与逐跳头，保留其余（含 x-litellm-call-id）。
// 供 /v1/* 各代理端点复用（#23 models，后续 chat/embeddings 同口径）。
func CopySafeHeaders(dst, src http.Header) {
	for name, values := range src {
		if isStripped(name) {
			continue
		}
		for _, v := range values {
			dst.Add(name, v)
		}
	}
}

// isStripped 判定一个响应头是否应被剥除（成本敏感 / 逐跳）。
func isStripped(name string) bool {
	lower := strings.ToLower(name)
	if _, ok := costSensitiveHeaders[lower]; ok {
		return true
	}
	if _, ok := hopByHopHeaders[lower]; ok {
		return true
	}
	for _, p := range costSensitivePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
