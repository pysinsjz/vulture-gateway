package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("启动 miniredis 失败: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func TestGWCodeStore_SingleUse(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewGWCodeStore(rdb, 60*time.Second)
	ctx := context.Background()

	code, err := store.Issue(ctx, GWCode{CodeChallenge: "cc", UserUUID: "usr_1", RedirectURI: "http://127.0.0.1:5000/callback"})
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}

	got, found, err := store.Consume(ctx, code)
	if err != nil || !found {
		t.Fatalf("首次 Consume 应成功, found=%v err=%v", found, err)
	}
	if got.UserUUID != "usr_1" || got.CodeChallenge != "cc" {
		t.Errorf("Consume 数据不符: %+v", got)
	}

	// 复用：第二次取用必须失败。
	if _, found, _ := store.Consume(ctx, code); found {
		t.Error("GW_CODE 复用应失败（单次使用）")
	}
}

func TestGWCodeStore_TTLExpiry(t *testing.T) {
	rdb, mr := testRedis(t)
	store := NewGWCodeStore(rdb, 60*time.Second)
	ctx := context.Background()

	code, err := store.Issue(ctx, GWCode{CodeChallenge: "cc", UserUUID: "usr_1"})
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}

	mr.FastForward(61 * time.Second)

	if _, found, _ := store.Consume(ctx, code); found {
		t.Error("GW_CODE 超过 60s TTL 应已过期")
	}
}

func TestGWCodeStore_ConsumeUnknown(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewGWCodeStore(rdb, 60*time.Second)
	if _, found, err := store.Consume(context.Background(), "gwc_nope"); err != nil || found {
		t.Errorf("未知 code 应 found=false 无错, found=%v err=%v", found, err)
	}
}

func TestAuthzStore_SaveTakeOnce(t *testing.T) {
	rdb, _ := testRedis(t)
	store := NewAuthzStore(rdb, 10*time.Minute)
	ctx := context.Background()

	req := AuthzRequest{OrigState: "orig", CodeChallenge: "cc", RedirectURI: "http://127.0.0.1:5000/callback"}
	if err := store.Save(ctx, "st_link", req); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}

	got, found, err := store.Take(ctx, "st_link")
	if err != nil || !found {
		t.Fatalf("Take 应成功, found=%v err=%v", found, err)
	}
	if got != req {
		t.Errorf("Take 数据不符: %+v != %+v", got, req)
	}

	// 一次性：第二次取回失败。
	if _, found, _ := store.Take(ctx, "st_link"); found {
		t.Error("authz 应一次性，第二次 Take 应失败")
	}
}
