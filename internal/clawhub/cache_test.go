package clawhub

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// fakePackagesClient 是 PackagesClient 的最小内存假实现，按 ListPackages/GetPackage 计数。
// 其他方法 panic 提示用例覆盖错位。
type fakePackagesClient struct {
	listCalls atomic.Int64
	getCalls  atomic.Int64

	listFn func(context.Context, ListParams) (*PackagePage, error)
	getFn  func(context.Context, string) (*PackageDetail, error)
}

func (f *fakePackagesClient) ListPackages(ctx context.Context, p ListParams) (*PackagePage, error) {
	f.listCalls.Add(1)
	if f.listFn != nil {
		return f.listFn(ctx, p)
	}
	cur := "next-cursor"
	return &PackagePage{Items: []PackageListItem{{Name: "demo"}}, NextCursor: &cur}, nil
}

func (f *fakePackagesClient) GetPackage(ctx context.Context, name string) (*PackageDetail, error) {
	f.getCalls.Add(1)
	if f.getFn != nil {
		return f.getFn(ctx, name)
	}
	return &PackageDetail{Package: PackageInfo{Name: name, DisplayName: name}}, nil
}

func (f *fakePackagesClient) GetPackageRelease(context.Context, string, string) (*PackageReleaseDetail, error) {
	panic("not expected")
}
func (f *fakePackagesClient) ListPackageReleases(context.Context, string, PageParams) (*PackageReleasePage, error) {
	panic("not expected")
}
func (f *fakePackagesClient) PackageDownloadStreamURL(string, string) string {
	panic("not expected")
}
func (f *fakePackagesClient) PackageArtifactStreamURL(string, string) string {
	panic("not expected")
}
func (f *fakePackagesClient) PackageSecurity(context.Context, string, string) (*PluginTrust, error) {
	panic("not expected")
}

func newTestCacheRDB(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
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

// 命中：连续两次同参数调用 ListPackages，第二次走 Redis 缓存，inner 仅被调一次。
func TestCachingPackages_ListHitsAfterFirstCall(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	for i := 0; i < 3; i++ {
		page, err := c.ListPackages(context.Background(), ListParams{Limit: 20, Sort: "updated"})
		if err != nil {
			t.Fatalf("第%d次 ListPackages 失败: %v", i, err)
		}
		if len(page.Items) != 1 || page.Items[0].Name != "demo" {
			t.Fatalf("第%d次响应不符: %+v", i, page)
		}
	}
	if got := fake.listCalls.Load(); got != 1 {
		t.Errorf("inner ListPackages 调用次数 = %d, 期望 1（首次 miss，后续 hit）", got)
	}
}

// 不同参数走不同 key，互不命中——验证 key 编码确实带参数。
func TestCachingPackages_DifferentParamsDifferentKey(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	_, _ = c.ListPackages(context.Background(), ListParams{Limit: 20, Sort: "updated"})
	_, _ = c.ListPackages(context.Background(), ListParams{Limit: 20, Sort: "trending"})
	_, _ = c.ListPackages(context.Background(), ListParams{Limit: 20, Sort: "updated"}) // 应命中第一次

	if got := fake.listCalls.Load(); got != 2 {
		t.Errorf("inner ListPackages 调用次数 = %d, 期望 2（updated 一次 + trending 一次）", got)
	}
}

// 错误不缓存：inner 失败后再次调用仍透传到 inner（不会命中错误响应）。
func TestCachingPackages_ErrorsNotCached(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	upstreamErr := errors.New("upstream boom")
	fake := &fakePackagesClient{listFn: func(context.Context, ListParams) (*PackagePage, error) {
		return nil, upstreamErr
	}}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	for i := 0; i < 3; i++ {
		_, err := c.ListPackages(context.Background(), ListParams{Limit: 10})
		if !errors.Is(err, upstreamErr) {
			t.Fatalf("第%d次错误不透传: got %v", i, err)
		}
	}
	if got := fake.listCalls.Load(); got != 3 {
		t.Errorf("inner ListPackages 调用次数 = %d, 期望 3（错误不缓存，每次都穿透）", got)
	}
}

// Redis GET 报错 → fail-open 穿透到 inner（不返回错误）。
func TestCachingPackages_RedisGetErrorFailsOpen(t *testing.T) {
	rdb, mr := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	mr.SetError("forced redis failure")
	defer mr.SetError("")

	page, err := c.ListPackages(context.Background(), ListParams{Limit: 20})
	if err != nil {
		t.Fatalf("Redis 异常时应 fail-open，实际返错: %v", err)
	}
	if page == nil || len(page.Items) != 1 {
		t.Fatalf("响应不符: %+v", page)
	}
	if got := fake.listCalls.Load(); got != 1 {
		t.Errorf("inner 应被穿透调用 1 次，实际 %d", got)
	}
}

// Redis 全程不可用 → 多次调用每次都穿透 inner（GET 与 SET 都失败但请求成功）。
func TestCachingPackages_RedisCompletelyDownStillServes(t *testing.T) {
	rdb, mr := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	mr.SetError("forced redis failure")
	defer mr.SetError("")

	for i := 0; i < 3; i++ {
		if _, err := c.ListPackages(context.Background(), ListParams{Limit: 20}); err != nil {
			t.Fatalf("第%d次失败: %v", i, err)
		}
	}
	if got := fake.listCalls.Load(); got != 3 {
		t.Errorf("Redis 全程异常时应每次都穿透，调用次数 = %d, 期望 3", got)
	}
}

// singleflight 并发去重：N 个并发同 key 请求，inner 仅被调一次。
func TestCachingPackages_SingleflightDedup(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	release := make(chan struct{})
	fake := &fakePackagesClient{listFn: func(context.Context, ListParams) (*PackagePage, error) {
		<-release // 阻塞直到所有 goroutine 都已发起请求
		cur := "x"
		return &PackagePage{Items: []PackageListItem{{Name: "demo"}}, NextCursor: &cur}, nil
	}}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := c.ListPackages(context.Background(), ListParams{Limit: 50}); err != nil {
				errs <- err
			}
		}()
	}
	// 给所有 goroutine 一点时间发起请求并进入 singleflight 等待
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发请求出错: %v", err)
	}

	if got := fake.listCalls.Load(); got != 1 {
		t.Errorf("singleflight 失效，inner 调用次数 = %d, 期望 1", got)
	}
}

// TTL=0 → 装饰器整层短路，每次都透传 inner，Redis 不写入任何 key。
func TestCachingPackages_TTLZeroDisablesCache(t *testing.T) {
	rdb, mr := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 0)

	for i := 0; i < 3; i++ {
		if _, err := c.ListPackages(context.Background(), ListParams{Limit: 20}); err != nil {
			t.Fatalf("第%d次失败: %v", i, err)
		}
	}
	if got := fake.listCalls.Load(); got != 3 {
		t.Errorf("禁用缓存时 inner 调用次数 = %d, 期望 3", got)
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Errorf("禁用缓存时 Redis 不应写入 key，实际 %v", keys)
	}
}

// rdb=nil → 装饰器整层短路，行为同 TTL=0。
func TestCachingPackages_NilRedisDisablesCache(t *testing.T) {
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, nil, 5*time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := c.ListPackages(context.Background(), ListParams{Limit: 20}); err != nil {
			t.Fatalf("第%d次失败: %v", i, err)
		}
	}
	if got := fake.listCalls.Load(); got != 3 {
		t.Errorf("rdb=nil 时 inner 调用次数 = %d, 期望 3", got)
	}
}

// GetPackage 详情缓存路径同 list：第一次 miss 后续 hit。
func TestCachingPackages_DetailHitsAfterFirstCall(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	for i := 0; i < 3; i++ {
		d, err := c.GetPackage(context.Background(), "slack-mcp")
		if err != nil {
			t.Fatalf("第%d次 GetPackage 失败: %v", i, err)
		}
		if d.Package.Name != "slack-mcp" {
			t.Fatalf("第%d次响应不符: %+v", i, d.Package)
		}
	}
	if got := fake.getCalls.Load(); got != 1 {
		t.Errorf("inner GetPackage 调用次数 = %d, 期望 1", got)
	}
}

// 不同 slug → 不同 key，互不命中。
func TestCachingPackages_DetailDifferentSlugDifferentKey(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	_, _ = c.GetPackage(context.Background(), "a")
	_, _ = c.GetPackage(context.Background(), "b")
	_, _ = c.GetPackage(context.Background(), "a") // 命中第一次

	if got := fake.getCalls.Load(); got != 2 {
		t.Errorf("inner 调用次数 = %d, 期望 2", got)
	}
}

// jitterTTL：实际 TTL 落在 [base-delta, base+delta]，delta = min(30s, base/10)。
// 验 1m base（delta=6s）与 5m base（delta=30s）两个挡位。
func TestJitterTTL_WithinExpectedBand(t *testing.T) {
	tests := []struct {
		base  time.Duration
		delta time.Duration
	}{
		{base: 1 * time.Minute, delta: 6 * time.Second},
		{base: 5 * time.Minute, delta: 30 * time.Second},
		{base: 10 * time.Minute, delta: 30 * time.Second}, // 10m/10=1m，被夹到 30s 上限
	}
	for _, tc := range tests {
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("key-%d-%d", tc.base, i)
			got := jitterTTL(key, tc.base)
			if got < tc.base-tc.delta || got > tc.base+tc.delta {
				t.Errorf("base=%s delta=%s: ttl=%s 越界", tc.base, tc.delta, got)
			}
		}
	}
}

// jitterTTL：同一 key 多次调用必须返回同一 TTL（保证多实例填同一 key 时过期时刻一致）。
func TestJitterTTL_StableForSameKey(t *testing.T) {
	base := 5 * time.Minute
	first := jitterTTL("stable-key", base)
	for i := 0; i < 10; i++ {
		if got := jitterTTL("stable-key", base); got != first {
			t.Errorf("同 key TTL 不稳定: 第%d 次 %s != %s", i, got, first)
		}
	}
}

// jitterTTL(_, 0) → 0（禁用挡位的安全返回）。
func TestJitterTTL_ZeroBase(t *testing.T) {
	if got := jitterTTL("any", 0); got != 0 {
		t.Errorf("base=0 应返 0, 实际 %s", got)
	}
}

// 缓存 key 实际写入了 Redis 且带 gw:hub: 前缀（接 SCAN MATCH gw:hub:* 清缓存的运维路径）。
func TestCachingPackages_KeyHasPrefix(t *testing.T) {
	rdb, mr := newTestCacheRDB(t)
	fake := &fakePackagesClient{}
	c := NewCachingPackagesClient(fake, rdb, 5*time.Minute)

	_, _ = c.GetPackage(context.Background(), "slack-mcp")
	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("期望写入 1 个 key, 实际 %v", keys)
	}
	want := "gw:hub:package:slack-mcp"
	if keys[0] != want {
		t.Errorf("key = %q, 期望 %q", keys[0], want)
	}
}
