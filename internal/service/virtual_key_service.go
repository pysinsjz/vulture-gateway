package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/dao"
	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// VKeyLocker 是分布式锁契约（auth.Locker 满足）。圈住整个 get-or-create，防并发首签出孤儿 key（ADR-0014 防双签 ①）。
type VKeyLocker interface {
	Acquire(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Release(ctx context.Context, key string)
}

const (
	vkeyLockTTL       = 10 * time.Second      // 锁寿命：秒级，签发是一次 litellm 往返
	vkeyLockWaitRetry = 50 * time.Millisecond // 等锁轮询间隔
	vkeyLockMaxWait   = 3 * time.Second       // 等锁上限，超时降级裸签（DB 唯一约束 + 冲突回删兜底）
	// vkeyMaxBudgetFuse 是纵深防御保险丝：数值故意大到永不触发（B 当前挂空），待定价文档落地后重算（ADR-0014）。
	vkeyMaxBudgetFuse = 9999999.0
	orphanDeleteTTL   = 5 * time.Second // 孤儿 key 回删用独立短 ctx
)

// VirtualKeyService 是 ADR-0014 / 0016 的单一入口：按用户 get-or-create litellm virtual key + 自愈轮换 + 删除接缝。
// DB 为真相源，Redis 缓存热路径，分布式锁 + 唯一约束 + 冲突回删三重防孤儿。限额权威仍在网关侧（不改 ADR-0005/0008）。
//
// ADR-0016：签发归属由 defaultTeamAlias 指定（如 "team-pro"），签发前调 admin.ListTeams 解析为 team_id；
// 不缓存解析结果（team 重建立刻恢复）；alias 不存在 / 重复 → fail-closed（lazy 重试）。
type VirtualKeyService struct {
	repo             dao.UserVirtualKeyRepository
	admin            litellm.AdminClient
	cache            VKeyCache
	locker           VKeyLocker
	defaultTeamAlias string // 签发时归属的 litellm team alias（ADR-0016，如 team-pro/team-free）
}

// NewVirtualKeyService 构造服务。defaultTeamAlias 为签发用户 key 时归属的 litellm team 别名；
// 调用方（wire/config）必须传非空值——config.validate() 已强制必填校验（ADR-0016）。
func NewVirtualKeyService(repo dao.UserVirtualKeyRepository, admin litellm.AdminClient, cache VKeyCache, locker VKeyLocker, defaultTeamAlias string) *VirtualKeyService {
	return &VirtualKeyService{repo: repo, admin: admin, cache: cache, locker: locker, defaultTeamAlias: defaultTeamAlias}
}

func vkeyAlias(userUUID string) string   { return "user-" + userUUID }
func vkeyLockKey(userUUID string) string { return "lock:vkey:" + userUUID }

// GetOrCreateVirtualKey 是单一入口（eager 注册 + lazy 推理双触发）：缓存 → DB → 锁内签发。幂等。
func (s *VirtualKeyService) GetOrCreateVirtualKey(ctx context.Context, userUUID string) (string, error) {
	if userUUID == "" {
		return "", fmt.Errorf("userUUID 为空，无法签发 virtual key")
	}
	// 1. 缓存命中（热路径）。
	if key, ok, err := s.cache.Get(ctx, userUUID); err == nil && ok && key != "" {
		return key, nil
	}
	// 2. DB 命中（active）回填缓存。
	if key, ok, err := s.lookupActive(ctx, userUUID); err != nil {
		return "", err
	} else if ok {
		s.fillCache(ctx, userUUID, key)
		return key, nil
	}
	// 3. 未签发：加锁圈住 sign-or-recheck。
	return s.signUnderLock(ctx, userUUID)
}

// RevokeAndRegenerate 自愈轮换（ADR-0014 失败处理 ②）：清缓存 + 签新 key + 原行覆盖（保 1:1）+ 删旧上游 key。
// 用于「库里 key 被 litellm 拒绝」的一次性自愈，返回新 key 供本次请求重试。
func (s *VirtualKeyService) RevokeAndRegenerate(ctx context.Context, userUUID string) (string, error) {
	if userUUID == "" {
		return "", fmt.Errorf("userUUID 为空，无法轮换 virtual key")
	}
	lockKey := vkeyLockKey(userUUID)
	if acquired := s.tryLock(ctx, userUUID, lockKey); acquired {
		defer s.locker.Release(ctx, lockKey)
	}

	_ = s.cache.Del(ctx, userUUID)
	old, found, err := s.repo.GetByUserUUID(ctx, userUUID)
	if err != nil {
		return "", err
	}

	gen, err := s.sign(ctx, userUUID)
	if err != nil {
		return "", err
	}

	// 无旧行（自愈与删除并发等边角）：退化为首签插入路径。
	if !found {
		return s.persistFirst(ctx, userUUID, gen)
	}

	// 原行覆盖：保 1:1 不破 user_uuid 唯一约束。team_alias 刷新为当前配置值（ADR-0016）。
	if err := s.repo.Replace(ctx, userUUID, gen.Key, vkeyAlias(userUUID), gen.TokenID, s.defaultTeamAlias); err != nil {
		s.deleteOrphan(gen.Key)
		return "", fmt.Errorf("覆盖 virtual key 失败: %w", err)
	}
	// 删旧上游 key（best-effort：已被 litellm 拒就当已删）。
	if old.LitellmKey != "" && old.LitellmKey != gen.Key {
		s.deleteOrphan(old.LitellmKey)
	}
	s.fillCache(ctx, userUUID, gen.Key)
	return gen.Key, nil
}

// DeleteForUser 删除某用户的 virtual key（删/封用户接缝，v1 未接线，ADR-0014 生命周期范围）。
func (s *VirtualKeyService) DeleteForUser(ctx context.Context, userUUID string) error {
	_ = s.cache.Del(ctx, userUUID)
	vk, found, err := s.repo.GetByUserUUID(ctx, userUUID)
	if err != nil {
		return err
	}
	if found && vk.LitellmKey != "" {
		if err := s.admin.DeleteKey(ctx, vk.LitellmKey); err != nil {
			return fmt.Errorf("删除 litellm key 失败: %w", err)
		}
	}
	return s.repo.DeleteByUserUUID(ctx, userUUID)
}

// ---- 内部 ----

func (s *VirtualKeyService) lookupActive(ctx context.Context, userUUID string) (string, bool, error) {
	vk, found, err := s.repo.GetByUserUUID(ctx, userUUID)
	if err != nil {
		return "", false, err
	}
	if !found || vk.Status != model.VirtualKeyStatusActive || vk.LitellmKey == "" {
		return "", false, nil
	}
	return vk.LitellmKey, true, nil
}

func (s *VirtualKeyService) signUnderLock(ctx context.Context, userUUID string) (string, error) {
	lockKey := vkeyLockKey(userUUID)
	if acquired := s.tryLock(ctx, userUUID, lockKey); acquired {
		defer s.locker.Release(ctx, lockKey)
	}
	// 锁内一次取行：等锁期间他人可能已签；非 active 行（如未来 ban 留下的 revoked）走原行覆盖而非插入（保 1:1）。
	vk, found, err := s.repo.GetByUserUUID(ctx, userUUID)
	if err != nil {
		return "", err
	}
	if found && vk.Status == model.VirtualKeyStatusActive && vk.LitellmKey != "" {
		s.fillCache(ctx, userUUID, vk.LitellmKey)
		return vk.LitellmKey, nil
	}
	gen, err := s.sign(ctx, userUUID)
	if err != nil {
		return "", err
	}
	if found {
		// 已有行但不可用：原行覆盖（避免 Create 撞 user_uuid 唯一约束）。team_alias 刷新为当前配置值（ADR-0016）。
		if err := s.repo.Replace(ctx, userUUID, gen.Key, vkeyAlias(userUUID), gen.TokenID, s.defaultTeamAlias); err != nil {
			s.deleteOrphan(gen.Key)
			return "", fmt.Errorf("覆盖 virtual key 失败: %w", err)
		}
		s.fillCache(ctx, userUUID, gen.Key)
		return gen.Key, nil
	}
	return s.persistFirst(ctx, userUUID, gen)
}

// persistFirst 首签落库：唯一冲突时删孤儿回查既有行（防孤儿 ②③）。team_alias 写入当前配置值（ADR-0016）。
func (s *VirtualKeyService) persistFirst(ctx context.Context, userUUID string, gen *litellm.GeneratedKey) (string, error) {
	vk := &model.UserVirtualKey{
		UserUUID:   userUUID,
		LitellmKey: gen.Key,
		KeyAlias:   vkeyAlias(userUUID),
		TokenID:    gen.TokenID,
		TeamAlias:  s.defaultTeamAlias,
		Status:     model.VirtualKeyStatusActive,
	}
	inserted, err := s.repo.Create(ctx, vk)
	if err != nil {
		s.deleteOrphan(gen.Key)
		return "", fmt.Errorf("落库 virtual key 失败: %w", err)
	}
	if !inserted {
		// 并发竞态：他人抢先插入。删自己签的孤儿，回查既有行返回。
		s.deleteOrphan(gen.Key)
		key, ok, err := s.lookupActive(ctx, userUUID)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("virtual key 冲突后回查为空 user=%s", userUUID)
		}
		s.fillCache(ctx, userUUID, key)
		return key, nil
	}
	s.fillCache(ctx, userUUID, gen.Key)
	return gen.Key, nil
}

func (s *VirtualKeyService) sign(ctx context.Context, userUUID string) (*litellm.GeneratedKey, error) {
	// ADR-0016：签发前调 litellm /team/list 把 defaultTeamAlias 解析为 team_id；零缓存，team 重建立刻恢复。
	// 不下发 models 字段——team 的 models 列表是模型权限的单一真相源（workaround litellm bug #3275）。
	// alias 不存在 / 重复 / list 失败：resolveTeamID 返错，签发本次失败，lazy 重试或返 upstream_unavailable。
	teamID, err := s.resolveTeamID(ctx)
	if err != nil {
		return nil, fmt.Errorf("签发 virtual key 失败: %w", err)
	}
	gen, err := s.admin.GenerateKey(ctx, litellm.GenerateKeyParams{
		KeyAlias:  vkeyAlias(userUUID),
		UserID:    userUUID,
		TeamID:    teamID,
		MaxBudget: vkeyMaxBudgetFuse,
	})
	if err != nil {
		return nil, fmt.Errorf("签发 virtual key 失败: %w", err)
	}
	return gen, nil
}

// resolveTeamID 把 defaultTeamAlias 解析为 litellm team_id（ADR-0016）。
// 0 匹配 → fail-closed（alias 不存在）；多匹配 → fail-closed（歧义，运维需消除）。
func (s *VirtualKeyService) resolveTeamID(ctx context.Context) (string, error) {
	teams, err := s.admin.ListTeams(ctx)
	if err != nil {
		return "", fmt.Errorf("拉取 team 列表失败: %w", err)
	}
	var matched []litellm.Team
	for _, t := range teams {
		if t.Alias == s.defaultTeamAlias {
			matched = append(matched, t)
		}
	}
	switch len(matched) {
	case 0:
		return "", fmt.Errorf("team alias %q 在 litellm 不存在（请在 litellm 后台建好该 team）", s.defaultTeamAlias)
	case 1:
		return matched[0].ID, nil
	default:
		ids := make([]string, len(matched))
		for i, t := range matched {
			ids[i] = t.ID
		}
		return "", fmt.Errorf("team alias %q 在 litellm 匹配多个 team_id: %v（运维需消除歧义）", s.defaultTeamAlias, ids)
	}
}

// tryLock 在 vkeyLockMaxWait 内争锁；超时返回 false 降级裸签（DB 唯一约束 + 冲突回删兜底）。
func (s *VirtualKeyService) tryLock(ctx context.Context, userUUID, lockKey string) bool {
	deadline := time.Now().Add(vkeyLockMaxWait)
	for {
		ok, err := s.locker.Acquire(ctx, lockKey, vkeyLockTTL)
		if err != nil {
			log.Printf("[vkey] 获取分布式锁失败，降级裸签 user=%s: %v", userUUID, err)
			return false
		}
		if ok {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(vkeyLockWaitRetry):
		}
	}
}

// deleteOrphan best-effort 删除孤儿 key，用独立短 ctx（请求 ctx 可能已是失败诱因）。
func (s *VirtualKeyService) deleteOrphan(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), orphanDeleteTTL)
	defer cancel()
	if err := s.admin.DeleteKey(ctx, key); err != nil {
		log.Printf("[vkey] 删除孤儿 key 失败（需人工巡检 litellm）: %v", err)
	}
}

func (s *VirtualKeyService) fillCache(ctx context.Context, userUUID, key string) {
	if err := s.cache.Set(ctx, userUUID, key); err != nil {
		log.Printf("[vkey] 回填 virtual key 缓存失败 user=%s: %v", userUUID, err)
	}
}
