package clawhub

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// cachingSkillsClient 是 SkillsClient 的 raw 响应缓存装饰器。
// 缓存方法：ListSkills / GetSkill / ListSkillCategoriesDictionary
// （覆盖 skills list / detail / categories 三个对外端点的上游数据源）。
// 其余方法（版本历史、版本详情、resolve、下载、verdicts）原样透传——见设计访谈 Q3。
type cachingSkillsClient struct {
	inner SkillsClient
	c     *cache
}

// NewCachingSkillsClient 用 Redis raw 缓存包装一层 inner。
// ttl<=0 或 rdb==nil 时缓存层短路（直接透传 inner），实现"cache_ttl: 0s 紧急止血"语义。
func NewCachingSkillsClient(inner SkillsClient, rdb *redis.Client, ttl time.Duration) SkillsClient {
	return &cachingSkillsClient{inner: inner, c: newCache(rdb, ttl)}
}

func (c *cachingSkillsClient) ListSkills(ctx context.Context, params SkillListParams) (*SkillPage, error) {
	key := "skills?" + skillsListQuery(params)
	return cachedGet(ctx, c.c, "skills_list", key, func(ctx context.Context) (*SkillPage, error) {
		return c.inner.ListSkills(ctx, params)
	})
}

func (c *cachingSkillsClient) GetSkill(ctx context.Context, slug string) (*SkillDetail, error) {
	key := "skill:" + slug
	return cachedGet(ctx, c.c, "skill_detail", key, func(ctx context.Context) (*SkillDetail, error) {
		return c.inner.GetSkill(ctx, slug)
	})
}

// 以下为透传：版本历史 / 版本详情 / resolve / 下载 URL / verdicts 都不缓存（见设计访谈 Q3）。

func (c *cachingSkillsClient) ListSkillVersions(ctx context.Context, slug string, page PageParams) (*SkillVersionPage, error) {
	return c.inner.ListSkillVersions(ctx, slug, page)
}

func (c *cachingSkillsClient) GetSkillVersion(ctx context.Context, slug, version string) (*SkillVersionDetail, error) {
	return c.inner.GetSkillVersion(ctx, slug, version)
}

func (c *cachingSkillsClient) ResolveSkill(ctx context.Context, slug, hash string) (*ResolveResult, error) {
	return c.inner.ResolveSkill(ctx, slug, hash)
}

func (c *cachingSkillsClient) SkillDownloadStreamURL(slug, version string) string {
	return c.inner.SkillDownloadStreamURL(slug, version)
}

func (c *cachingSkillsClient) SecurityVerdicts(ctx context.Context, items []VerdictRequestItem) (*SecurityVerdictResult, error) {
	return c.inner.SecurityVerdicts(ctx, items)
}

// ListSkillCategoriesDictionary 复用 clawhub.cache_ttl（无参，key 固定）。
// cache_ttl=0 时整层短路（同 ListSkills）；用 cachedGetSlice 适配 []T 形态。
func (c *cachingSkillsClient) ListSkillCategoriesDictionary(ctx context.Context) ([]CategoryDict, error) {
	return cachedGetSlice(ctx, c.c, "category_dict_skill", "category_dict_skill", func(ctx context.Context) ([]CategoryDict, error) {
		return c.inner.ListSkillCategoriesDictionary(ctx)
	})
}

// skillsListQuery 把 SkillListParams 编码为缓存键的明文 query 段（url.Values 自带字典序），
// 与 httpClient.ListSkills 的下发规则保持一致：空字段不下发。
func skillsListQuery(p SkillListParams) string {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	setIfNotEmpty(q, "cursor", p.Cursor)
	setIfNotEmpty(q, "sort", p.Sort)
	setIfNotEmpty(q, "category", p.Category)
	return q.Encode()
}
