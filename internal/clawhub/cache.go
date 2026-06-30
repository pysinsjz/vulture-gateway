package clawhub

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

// cachePrefix 是所有 ClawHub raw 响应缓存的命名空间前缀（与 OTP / vkey 等其他 Redis 用法物理隔离）。
const cachePrefix = "gw:hub:"

// redisOpTimeout 是单次 Redis GET/SET 的硬超时。Redis 慢/抖动时不应让"加缓存"
// 反而变成"两次都慢"——超时即视为 miss / SET 失败（fail-open，见 cachedGet）。
const redisOpTimeout = 200 * time.Millisecond

// cache 是装饰器共享的横切组件束：Redis 句柄 + singleflight 防击穿 + 基础 TTL。
// ttl<=0 时整层短路（直接穿透 inner），实现配置侧"cache_ttl: 0s 紧急止血"语义。
type cache struct {
	rdb *redis.Client
	sf  singleflight.Group
	ttl time.Duration
}

// newCache 构造缓存组件。rdb 为 nil 或 ttl<=0 都视为禁用——cachedGet 会直接调用 fn。
func newCache(rdb *redis.Client, ttl time.Duration) *cache {
	return &cache{rdb: rdb, ttl: ttl}
}

// enabled 判定缓存是否生效。
func (c *cache) enabled() bool { return c != nil && c.rdb != nil && c.ttl > 0 }

// cachedGet 是 GET → singleflight → fn → SET 的统一模板。约束：
//   - 缓存禁用：直接调 fn。
//   - GET 命中：返回缓存值，DEBUG 日志。
//   - GET miss / GET 报错：经 singleflight 合并并发请求，仅一个调用穿透 fn；
//     GET 报错时 WARN 日志（fail-open 不静默，见设计访谈 Q8/Q12）。
//   - fn 成功：异步 SET（带 jitter），SET 报错仅 WARN，不影响返回值。
//   - fn 失败：错误不缓存（见 Q7），singleflight 内的并发请求共享同一份失败。
//
// jitter 实现细节：实际 TTL = base ± min(30s, base/10)，按 key 稳定派生（同一 key 命中
// 同一抖动量），避免不同实例 / 多次填充时刻不一致导致缓存语义漂移。
func cachedGet[T any](ctx context.Context, c *cache, endpoint, key string, fn func(context.Context) (*T, error)) (*T, error) {
	if !c.enabled() {
		return fn(ctx)
	}

	fullKey := cachePrefix + key

	if v, ok := cacheGet[T](ctx, c.rdb, endpoint, fullKey); ok {
		return v, nil
	}

	v, err, _ := c.sf.Do(fullKey, func() (any, error) {
		// 单飞期间 double-check：可能首个等待者已经把值塞回。
		if v, ok := cacheGet[T](ctx, c.rdb, endpoint, fullKey); ok {
			return v, nil
		}
		out, err := fn(ctx)
		if err != nil {
			return nil, err // 错误不缓存：直接上抛，singleflight 内的等待者共享这次失败
		}
		cacheSet(ctx, c.rdb, endpoint, fullKey, out, c.ttl)
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return v.(*T), nil
}

// cachedGetSlice 是 cachedGet 的 slice 适配器：缓存层只持指针，slice 用一层 wrap 转回。
// 用于无参数、返回 []T 的 ClawHub 端点（如分类字典）。
func cachedGetSlice[T any](ctx context.Context, c *cache, endpoint, key string, fn func(context.Context) ([]T, error)) ([]T, error) {
	type wrap struct {
		Items []T `json:"items"`
	}
	v, err := cachedGet(ctx, c, endpoint, key, func(ctx context.Context) (*wrap, error) {
		items, err := fn(ctx)
		if err != nil {
			return nil, err
		}
		return &wrap{Items: items}, nil
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.Items, nil
}

// cacheGet 从 Redis 读并 JSON 反序列化。命中返回 (value, true)；miss/超时/反序列化失败返回 (_, false)。
// 错误统一记 WARN（不静默），让运维 grep 得到 Redis 异常。
func cacheGet[T any](parent context.Context, rdb *redis.Client, endpoint, key string) (*T, bool) {
	ctx, cancel := context.WithTimeout(parent, redisOpTimeout)
	defer cancel()

	raw, err := rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		log.Printf("[clawhub-cache] miss endpoint=%s key=%s", endpoint, key)
		return nil, false
	}
	if err != nil {
		log.Printf("[clawhub-cache] WARN get error endpoint=%s key=%s err=%v (fail-open)", endpoint, key, err)
		return nil, false
	}

	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Printf("[clawhub-cache] WARN unmarshal error endpoint=%s key=%s err=%v (treat as miss)", endpoint, key, err)
		return nil, false
	}
	log.Printf("[clawhub-cache] hit endpoint=%s key=%s", endpoint, key)
	return &out, true
}

// cacheSet 写入 Redis，带 jitter；任何错误仅 WARN 不影响返回值（fail-open）。
func cacheSet(parent context.Context, rdb *redis.Client, endpoint, key string, val any, base time.Duration) {
	ctx, cancel := context.WithTimeout(parent, redisOpTimeout)
	defer cancel()

	raw, err := json.Marshal(val)
	if err != nil {
		log.Printf("[clawhub-cache] WARN marshal error endpoint=%s key=%s err=%v (skip set)", endpoint, key, err)
		return
	}
	ttl := jitterTTL(key, base)
	if err := rdb.Set(ctx, key, raw, ttl).Err(); err != nil {
		log.Printf("[clawhub-cache] WARN set error endpoint=%s key=%s err=%v (fail-open)", endpoint, key, err)
		return
	}
	log.Printf("[clawhub-cache] set endpoint=%s key=%s ttl=%s", endpoint, key, ttl)
}

// jitterTTL 返回 base ± delta，delta = min(30s, base/10)。按 key 稳定派生：同一 key 命中同一抖动量，
// 避免相邻分页 key 在同一秒批量过期触发雪崩，同时保证多实例填同一 key 的过期时刻一致。
func jitterTTL(key string, base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	delta := base / 10
	if delta > 30*time.Second {
		delta = 30 * time.Second
	}
	if delta <= 0 {
		return base
	}
	// 从 key 派生 [-delta, +delta] 区间内的稳定偏移
	sum := sha256.Sum256([]byte(key))
	bias := int64(binary.BigEndian.Uint64(sum[:8])) // 允许负值
	mod := bias % int64(2*delta)
	if mod < 0 {
		mod += int64(2 * delta)
	}
	offset := time.Duration(mod) - delta
	return base + offset
}
