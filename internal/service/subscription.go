package service

import "context"

// SubscriptionChecker 判定用户是否有有效订阅（#25 前置门禁，llm-proxy.md §4b）。
// 每个 Plan 都付费、无免费层（CONTEXT）：已登录但无有效订阅调推理端点 → 402。
//
// TODO(计费 C 域): 当前为占位实现，订阅状态由 config 注入布尔、与用户无关；
// 待计费域接入后改为按 userUUID 查真实 Subscription。
type SubscriptionChecker interface {
	HasActiveSubscription(ctx context.Context, userUUID string) (bool, error)
}

// stubSubscriptionChecker 是占位实现：返回固定布尔（来自 config），与用户无关。
type stubSubscriptionChecker struct {
	active bool
}

// NewStubSubscriptionChecker 构造占位订阅检查器。
// active=false 时所有用户判无有效订阅（用于 #25 契约：触发 402）。
func NewStubSubscriptionChecker(active bool) SubscriptionChecker {
	return &stubSubscriptionChecker{active: active}
}

func (s *stubSubscriptionChecker) HasActiveSubscription(context.Context, string) (bool, error) {
	return s.active, nil
}
