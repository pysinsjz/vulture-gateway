package auth

import (
	"context"
	"testing"
	"time"
)

func TestAuthzStore_PeekDoesNotConsume(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewAuthzStore(rdb, 10*time.Minute)
	ctx := context.Background()

	req := AuthzRequest{OrigState: "orig", CodeChallenge: "cc", RedirectURI: "http://127.0.0.1:5000/callback"}
	if err := store.Save(ctx, "lk1", req); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}

	// 连续 Peek 两次都应命中（不消费）。
	for i := 0; i < 2; i++ {
		got, found, err := store.Peek(ctx, "lk1")
		if err != nil || !found {
			t.Fatalf("第 %d 次 Peek 应命中, found=%v err=%v", i+1, found, err)
		}
		if got != req {
			t.Errorf("Peek 数据不符: %+v", got)
		}
	}
	// Peek 之后仍可 Take 消费。
	if _, found, _ := store.Take(ctx, "lk1"); !found {
		t.Error("Peek 后 Take 仍应命中")
	}
	// Take 之后 Peek 不再命中。
	if _, found, _ := store.Peek(ctx, "lk1"); found {
		t.Error("Take 消费后 Peek 不应命中")
	}
}

func TestAuthzStore_PeekUnknown(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewAuthzStore(rdb, 10*time.Minute)
	if _, found, err := store.Peek(context.Background(), "nope"); err != nil || found {
		t.Errorf("未知 lk 应 found=false 无错, found=%v err=%v", found, err)
	}
}

func TestCSRFStore_IssueConsumeOnce(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewCSRFStore(rdb, 10*time.Minute)
	ctx := context.Background()

	token, err := store.Issue(ctx, "lk1")
	if err != nil || token == "" {
		t.Fatalf("Issue 应返回非空 token: %v", err)
	}

	// 正确 token 一次性通过。
	if ok, _ := store.Consume(ctx, "lk1", token); !ok {
		t.Error("正确 token 应通过")
	}
	// 复用失败。
	if ok, _ := store.Consume(ctx, "lk1", token); ok {
		t.Error("token 应一次性，复用应失败")
	}
}

func TestCSRFStore_ValidateDoesNotConsume(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewCSRFStore(rdb, 10*time.Minute)
	ctx := context.Background()

	token, err := store.Issue(ctx, "sid1")
	if err != nil || token == "" {
		t.Fatalf("Issue 应返回非空 token: %v", err)
	}

	// Validate 可多次命中（不消费），供页面作用域子请求（如忘记密码发码）重试。
	for i := 0; i < 2; i++ {
		if ok, err := store.Validate(ctx, "sid1", token); err != nil || !ok {
			t.Fatalf("第 %d 次 Validate 应命中, ok=%v err=%v", i+1, ok, err)
		}
	}
	// 错误 token / 未知 sid 不命中。
	if ok, _ := store.Validate(ctx, "sid1", "wrong"); ok {
		t.Error("错误 token 的 Validate 不应命中")
	}
	if ok, _ := store.Validate(ctx, "nope", token); ok {
		t.Error("未知 sid 的 Validate 不应命中")
	}
	// Validate 之后仍可 Consume（最终提交一次性消费）。
	if ok, _ := store.Consume(ctx, "sid1", token); !ok {
		t.Error("Validate 后 Consume 仍应命中")
	}
	if ok, _ := store.Validate(ctx, "sid1", token); ok {
		t.Error("Consume 消费后 Validate 不应再命中")
	}
}

func TestCSRFStore_WrongToken(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewCSRFStore(rdb, 10*time.Minute)
	ctx := context.Background()

	if _, err := store.Issue(ctx, "lk1"); err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if ok, _ := store.Consume(ctx, "lk1", "wrong-token"); ok {
		t.Error("错误 token 应失败")
	}
	// 错误 token 已消费绑定（GetDel），正确 token 此后也取不到——符合一次性语义。
	if ok, _ := store.Consume(ctx, "lk1", "anything"); ok {
		t.Error("已被取用后应一律失败")
	}
}
