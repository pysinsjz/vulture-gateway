package clawhub

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// cachingPackagesClient 是 PackagesClient 的 raw 响应缓存装饰器。
// 缓存方法：ListPackages / GetPackage（覆盖 plugins list / categories / detail 三个对外端点）。
// 其余方法（版本历史、版本详情、下载、security）原样透传——见设计访谈 Q3。
type cachingPackagesClient struct {
	inner PackagesClient
	c     *cache
}

// NewCachingPackagesClient 用 Redis raw 缓存包装一层 inner。
// ttl<=0 或 rdb==nil 时缓存层短路（直接透传 inner），实现"cache_ttl: 0s 紧急止血"语义。
func NewCachingPackagesClient(inner PackagesClient, rdb *redis.Client, ttl time.Duration) PackagesClient {
	return &cachingPackagesClient{inner: inner, c: newCache(rdb, ttl)}
}

func (c *cachingPackagesClient) ListPackages(ctx context.Context, params ListParams) (*PackagePage, error) {
	key := "packages?" + packagesListQuery(params)
	return cachedGet(ctx, c.c, "packages_list", key, func(ctx context.Context) (*PackagePage, error) {
		return c.inner.ListPackages(ctx, params)
	})
}

func (c *cachingPackagesClient) GetPackage(ctx context.Context, name string) (*PackageDetail, error) {
	key := "package:" + name
	return cachedGet(ctx, c.c, "package_detail", key, func(ctx context.Context) (*PackageDetail, error) {
		return c.inner.GetPackage(ctx, name)
	})
}

// 以下为透传：版本历史 / 版本详情 / 下载 URL / security 都不缓存（见设计访谈 Q3）。

func (c *cachingPackagesClient) GetPackageRelease(ctx context.Context, name, version string) (*PackageReleaseDetail, error) {
	return c.inner.GetPackageRelease(ctx, name, version)
}

func (c *cachingPackagesClient) ListPackageReleases(ctx context.Context, name string, page PageParams) (*PackageReleasePage, error) {
	return c.inner.ListPackageReleases(ctx, name, page)
}

func (c *cachingPackagesClient) PackageDownloadStreamURL(name, version string) string {
	return c.inner.PackageDownloadStreamURL(name, version)
}

func (c *cachingPackagesClient) PackageArtifactStreamURL(name, version string) string {
	return c.inner.PackageArtifactStreamURL(name, version)
}

func (c *cachingPackagesClient) PackageSecurity(ctx context.Context, name, version string) (*PluginTrust, error) {
	return c.inner.PackageSecurity(ctx, name, version)
}

// packagesListQuery 把 ListParams 编码为缓存键的明文 query 段（url.Values 自带字典序），
// 同 httpClient.ListPackages 的下发规则保持一致——空字段不下发，避免与不带 sort 等价请求碎片。
func packagesListQuery(p ListParams) string {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	setIfNotEmpty(q, "cursor", p.Cursor)
	setIfNotEmpty(q, "sort", p.Sort)
	setIfNotEmpty(q, "family", p.Family)
	setIfNotEmpty(q, "channel", p.Channel)
	setIfNotEmpty(q, "category", p.Category)
	return q.Encode()
}
