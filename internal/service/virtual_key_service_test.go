package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// ---- fakes ----

type fakeVKeyRepo struct {
	mu   sync.Mutex
	rows map[string]*model.UserVirtualKey
	// raceWinner 模拟并发竞态：本次 Create 调用时，先把 winner 行写入再返回 inserted=false（我方落库失败）。
	// 用于精确测试 persistFirst 的「冲突 → 删孤儿 → 回查既有行」分支（GetByUserUUID 此前已返回未找到）。
	raceWinner *model.UserVirtualKey
}

func newFakeVKeyRepo() *fakeVKeyRepo {
	return &fakeVKeyRepo{rows: map[string]*model.UserVirtualKey{}}
}

func (r *fakeVKeyRepo) GetByUserUUID(_ context.Context, userUUID string) (*model.UserVirtualKey, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vk, ok := r.rows[userUUID]; ok {
		cp := *vk
		return &cp, true, nil
	}
	return nil, false, nil
}

func (r *fakeVKeyRepo) Create(_ context.Context, vk *model.UserVirtualKey) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.raceWinner != nil {
		cp := *r.raceWinner
		r.rows[vk.UserUUID] = &cp
		r.raceWinner = nil
		return false, nil // 我方落库输给并发 winner（唯一冲突）
	}
	if _, ok := r.rows[vk.UserUUID]; ok {
		return false, nil // 唯一冲突
	}
	cp := *vk
	cp.ID = int64(len(r.rows) + 1)
	r.rows[vk.UserUUID] = &cp
	return true, nil
}

func (r *fakeVKeyRepo) Replace(_ context.Context, userUUID, key, alias, tokenID, teamAlias string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.rows[userUUID]
	if !ok {
		return errors.New("not found")
	}
	vk.LitellmKey = key
	vk.KeyAlias = alias
	vk.TokenID = tokenID
	vk.TeamAlias = teamAlias
	vk.Status = model.VirtualKeyStatusActive
	return nil
}

func (r *fakeVKeyRepo) DeleteByUserUUID(_ context.Context, userUUID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, userUUID)
	return nil
}

type fakeAdmin struct {
	mu         sync.Mutex
	genCalls   int
	delCalls   int
	listCalls  int
	deleted    []string
	nextKey    string
	failGen    bool
	keyCounter int
	lastTeamID string         // 记录最后一次 GenerateKey 收到的 TeamID（ADR-0016）
	lastBody   map[string]any // 记录最后一次 GenerateKey 收到的全部参数副本（断言 Models 字段是否消失）
	// teams 是 ListTeams 返回的固定列表；空＝默认含 alias=test-team-alias 的单项。
	teams []litellm.Team
	// failList true 时 ListTeams 返错（模拟 litellm 不可达）。
	failList bool
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{teams: []litellm.Team{{ID: "team-uuid-default", Alias: "test-team-alias"}}}
}

func (a *fakeAdmin) GenerateKey(_ context.Context, p litellm.GenerateKeyParams) (*litellm.GeneratedKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.genCalls++
	a.lastTeamID = p.TeamID
	// 拷一份「业务关心的字段」做断言用。
	a.lastBody = map[string]any{
		"key_alias":  p.KeyAlias,
		"user_id":    p.UserID,
		"team_id":    p.TeamID,
		"max_budget": p.MaxBudget,
	}
	if a.failGen {
		return nil, errors.New("litellm 不可达")
	}
	a.keyCounter++
	key := a.nextKey
	if key == "" {
		key = "sk-gen-" + p.UserID
	}
	return &litellm.GeneratedKey{Key: key, TokenID: "tok"}, nil
}

func (a *fakeAdmin) DeleteKey(_ context.Context, key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.delCalls++
	a.deleted = append(a.deleted, key)
	return nil
}

func (a *fakeAdmin) ListTeams(_ context.Context) ([]litellm.Team, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.listCalls++
	if a.failList {
		return nil, errors.New("litellm /team/list 不可达")
	}
	out := make([]litellm.Team, len(a.teams))
	copy(out, a.teams)
	return out, nil
}

type fakeCache struct {
	mu   sync.Mutex
	data map[string]string
}

func newFakeCache() *fakeCache { return &fakeCache{data: map[string]string{}} }

func (c *fakeCache) Get(_ context.Context, u string) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[u]
	return v, ok, nil
}
func (c *fakeCache) Set(_ context.Context, u, k string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[u] = k
	return nil
}
func (c *fakeCache) Del(_ context.Context, u string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, u)
	return nil
}

// fakeLocker 永远成功获锁（单测不验真实互斥，互斥由 Redis SetNX 保证）。
type fakeLocker struct{}

func (fakeLocker) Acquire(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return true, nil
}
func (fakeLocker) Release(_ context.Context, _ string) {}

// testTeamAlias 是新 svc 默认配的 team alias，匹配 fakeAdmin.teams 里预置的单项（ADR-0016）。
const testTeamAlias = "test-team-alias"

func newSvc() (*service.VirtualKeyService, *fakeVKeyRepo, *fakeAdmin, *fakeCache) {
	repo := newFakeVKeyRepo()
	admin := newFakeAdmin()
	cache := newFakeCache()
	svc := service.NewVirtualKeyService(repo, admin, cache, fakeLocker{}, testTeamAlias)
	return svc, repo, admin, cache
}

// ---- tests ----

// 缓存命中：不触 DB、不签发。
func TestGetOrCreate_CacheHit(t *testing.T) {
	svc, _, admin, cache := newSvc()
	_ = cache.Set(context.Background(), "u1", "sk-cached")

	key, err := svc.GetOrCreateVirtualKey(context.Background(), "u1")
	if err != nil || key != "sk-cached" {
		t.Fatalf("应命中缓存返回 sk-cached, 实际 key=%q err=%v", key, err)
	}
	if admin.genCalls != 0 {
		t.Errorf("缓存命中不应签发, genCalls=%d", admin.genCalls)
	}
}

// DB 命中（active）：回填缓存，不签发。
func TestGetOrCreate_DBHitFillsCache(t *testing.T) {
	svc, repo, admin, cache := newSvc()
	repo.rows["u1"] = &model.UserVirtualKey{UserUUID: "u1", LitellmKey: "sk-db", Status: model.VirtualKeyStatusActive}

	key, err := svc.GetOrCreateVirtualKey(context.Background(), "u1")
	if err != nil || key != "sk-db" {
		t.Fatalf("应命中 DB 返回 sk-db, 实际 key=%q err=%v", key, err)
	}
	if admin.genCalls != 0 {
		t.Errorf("DB 命中不应签发")
	}
	if v, _, _ := cache.Get(context.Background(), "u1"); v != "sk-db" {
		t.Errorf("应回填缓存, 实际 %q", v)
	}
}

// 首签：签发 + 落库 + 回填缓存。
func TestGetOrCreate_FirstSign(t *testing.T) {
	svc, repo, admin, cache := newSvc()

	key, err := svc.GetOrCreateVirtualKey(context.Background(), "u1")
	if err != nil || key != "sk-gen-u1" {
		t.Fatalf("应签发 sk-gen-u1, 实际 key=%q err=%v", key, err)
	}
	if admin.genCalls != 1 {
		t.Errorf("应签发一次, genCalls=%d", admin.genCalls)
	}
	if repo.rows["u1"] == nil || repo.rows["u1"].LitellmKey != "sk-gen-u1" {
		t.Errorf("应落库")
	}
	if repo.rows["u1"].KeyAlias != "user-u1" {
		t.Errorf("alias 应为 user-u1, 实际 %q", repo.rows["u1"].KeyAlias)
	}
	if v, _, _ := cache.Get(context.Background(), "u1"); v != "sk-gen-u1" {
		t.Errorf("应回填缓存")
	}
}

// 首签解析 alias 为 team_id 后下发；models 字段不下发（ADR-0016 workaround litellm bug #3275）。
func TestGetOrCreate_SignCarriesResolvedTeamID(t *testing.T) {
	svc, _, admin, _ := newSvc() // newSvc 注入 alias=testTeamAlias，fakeAdmin 预置匹配 team

	if _, err := svc.GetOrCreateVirtualKey(context.Background(), "u1"); err != nil {
		t.Fatalf("err=%v", err)
	}
	if admin.lastTeamID != "team-uuid-default" {
		t.Errorf("签发应下发解析后的 team_id=team-uuid-default, 实际 %q", admin.lastTeamID)
	}
	if admin.listCalls != 1 {
		t.Errorf("应调一次 /team/list 解析 alias, 实际 listCalls=%d", admin.listCalls)
	}
}

// 首签把 team_alias 快照写到落库行（ADR-0016 订阅升级钩子）。
func TestGetOrCreate_PersistsTeamAlias(t *testing.T) {
	svc, repo, _, _ := newSvc()

	if _, err := svc.GetOrCreateVirtualKey(context.Background(), "u1"); err != nil {
		t.Fatalf("err=%v", err)
	}
	if repo.rows["u1"] == nil {
		t.Fatal("应落库")
	}
	if repo.rows["u1"].TeamAlias != testTeamAlias {
		t.Errorf("team_alias 应快照为配置值 %q, 实际 %q", testTeamAlias, repo.rows["u1"].TeamAlias)
	}
}

// resolveTeamID alias 找不到 → fail-closed（签发不发起，返错）。
func TestSign_AliasNotFound_FailClosed(t *testing.T) {
	repo := newFakeVKeyRepo()
	admin := newFakeAdmin()
	admin.teams = []litellm.Team{{ID: "uuid-other", Alias: "team-other"}} // 没有 testTeamAlias
	svc := service.NewVirtualKeyService(repo, admin, newFakeCache(), fakeLocker{}, testTeamAlias)

	if _, err := svc.GetOrCreateVirtualKey(context.Background(), "u1"); err == nil {
		t.Fatal("alias 不存在应签发失败")
	}
	if admin.genCalls != 0 {
		t.Errorf("alias 解析失败不应调 GenerateKey, genCalls=%d", admin.genCalls)
	}
	if repo.rows["u1"] != nil {
		t.Errorf("失败不应落库")
	}
}

// resolveTeamID alias 匹配多个 team → fail-closed（ADR-0016：歧义不能静默选第一个）。
func TestSign_AliasDuplicate_FailClosed(t *testing.T) {
	repo := newFakeVKeyRepo()
	admin := newFakeAdmin()
	admin.teams = []litellm.Team{
		{ID: "uuid-a", Alias: testTeamAlias},
		{ID: "uuid-b", Alias: testTeamAlias}, // 同 alias 重复
	}
	svc := service.NewVirtualKeyService(repo, admin, newFakeCache(), fakeLocker{}, testTeamAlias)

	if _, err := svc.GetOrCreateVirtualKey(context.Background(), "u1"); err == nil {
		t.Fatal("alias 重复应 fail-closed 签发失败")
	}
	if admin.genCalls != 0 {
		t.Errorf("alias 重复不应调 GenerateKey, genCalls=%d", admin.genCalls)
	}
}

// resolveTeamID 列表 HTTP 失败 → 签发失败（透传）。
func TestSign_ListTeamsFailure_PropagatesError(t *testing.T) {
	repo := newFakeVKeyRepo()
	admin := newFakeAdmin()
	admin.failList = true
	svc := service.NewVirtualKeyService(repo, admin, newFakeCache(), fakeLocker{}, testTeamAlias)

	if _, err := svc.GetOrCreateVirtualKey(context.Background(), "u1"); err == nil {
		t.Fatal("/team/list 失败应签发失败")
	}
	if admin.genCalls != 0 {
		t.Errorf("ListTeams 失败不应调 GenerateKey")
	}
}

// revoked 行视为未签发，触发重签覆盖。
func TestGetOrCreate_RevokedRowResigns(t *testing.T) {
	svc, repo, admin, _ := newSvc()
	repo.rows["u1"] = &model.UserVirtualKey{UserUUID: "u1", LitellmKey: "sk-old", Status: model.VirtualKeyStatusRevoked}

	key, err := svc.GetOrCreateVirtualKey(context.Background(), "u1")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if admin.genCalls != 1 || key != "sk-gen-u1" {
		t.Errorf("revoked 应重签, genCalls=%d key=%q", admin.genCalls, key)
	}
}

// 签发失败（litellm 不可达）→ 返回错误，不落库。
func TestGetOrCreate_SignFailureNoPersist(t *testing.T) {
	svc, repo, admin, _ := newSvc()
	admin.failGen = true

	if _, err := svc.GetOrCreateVirtualKey(context.Background(), "u1"); err == nil {
		t.Fatal("签发失败应返回错误")
	}
	if repo.rows["u1"] != nil {
		t.Errorf("失败不应落库")
	}
}

// 并发竞态：lookup 未命中 → 签发 → 落库冲突（他人抢先）→ 删自签孤儿 + 回查 winner 行返回。
func TestGetOrCreate_ConflictDeletesOrphanAndReturnsExisting(t *testing.T) {
	svc, repo, admin, cache := newSvc()
	admin.nextKey = "sk-orphan" // 我方签出的孤儿 key
	// Create 时注入 winner：模拟另一并发请求已抢先插入 active 行。
	repo.raceWinner = &model.UserVirtualKey{UserUUID: "u1", LitellmKey: "sk-winner", Status: model.VirtualKeyStatusActive}

	key, err := svc.GetOrCreateVirtualKey(context.Background(), "u1")
	if err != nil || key != "sk-winner" {
		t.Fatalf("冲突后应返回 winner 的 sk-winner, 实际 key=%q err=%v", key, err)
	}
	if admin.genCalls != 1 {
		t.Errorf("应签发一次（随后冲突）, genCalls=%d", admin.genCalls)
	}
	// 自签的孤儿 key 应被回删（防孤儿 ③）。
	if len(admin.deleted) != 1 || admin.deleted[0] != "sk-orphan" {
		t.Errorf("应回删孤儿 sk-orphan, 实际 %+v", admin.deleted)
	}
	if v, _, _ := cache.Get(context.Background(), "u1"); v != "sk-winner" {
		t.Errorf("缓存应回填 winner, 实际 %q", v)
	}
}

// 自愈轮换：清缓存 + 签新 + 原行覆盖（含 team_alias 快照）+ 删旧上游 key。
func TestRevokeAndRegenerate_ReplacesAndDeletesOld(t *testing.T) {
	svc, repo, admin, cache := newSvc()
	repo.rows["u1"] = &model.UserVirtualKey{UserUUID: "u1", LitellmKey: "sk-old", KeyAlias: "user-u1", TeamAlias: "stale-old", Status: model.VirtualKeyStatusActive}
	_ = cache.Set(context.Background(), "u1", "sk-old")
	admin.nextKey = "sk-new"

	key, err := svc.RevokeAndRegenerate(context.Background(), "u1")
	if err != nil || key != "sk-new" {
		t.Fatalf("应返回新 key sk-new, 实际 key=%q err=%v", key, err)
	}
	if repo.rows["u1"].LitellmKey != "sk-new" {
		t.Errorf("应原行覆盖为 sk-new, 实际 %q", repo.rows["u1"].LitellmKey)
	}
	// ADR-0016：team_alias 应被刷新到当前配置值（旧的 stale-old 被覆盖）。
	if repo.rows["u1"].TeamAlias != testTeamAlias {
		t.Errorf("team_alias 应覆盖为当前配置 %q, 实际 %q", testTeamAlias, repo.rows["u1"].TeamAlias)
	}
	// 删旧上游 key。
	if len(admin.deleted) != 1 || admin.deleted[0] != "sk-old" {
		t.Errorf("应删旧 key sk-old, 实际 %+v", admin.deleted)
	}
	// 缓存回填为新 key。
	if v, _, _ := cache.Get(context.Background(), "u1"); v != "sk-new" {
		t.Errorf("缓存应回填 sk-new, 实际 %q", v)
	}
}

// 自愈轮换：无旧行（边角）→ 退化为首签插入。
func TestRevokeAndRegenerate_NoExistingRowInserts(t *testing.T) {
	svc, repo, admin, _ := newSvc()
	admin.nextKey = "sk-new"

	key, err := svc.RevokeAndRegenerate(context.Background(), "u1")
	if err != nil || key != "sk-new" {
		t.Fatalf("无旧行应首签, 实际 key=%q err=%v", key, err)
	}
	if repo.rows["u1"] == nil || repo.rows["u1"].LitellmKey != "sk-new" {
		t.Errorf("应插入新行")
	}
}

// DeleteForUser：删上游 key + 删库行 + 清缓存（接缝）。
func TestDeleteForUser(t *testing.T) {
	svc, repo, admin, cache := newSvc()
	repo.rows["u1"] = &model.UserVirtualKey{UserUUID: "u1", LitellmKey: "sk-x", Status: model.VirtualKeyStatusActive}
	_ = cache.Set(context.Background(), "u1", "sk-x")

	if err := svc.DeleteForUser(context.Background(), "u1"); err != nil {
		t.Fatalf("err=%v", err)
	}
	if repo.rows["u1"] != nil {
		t.Errorf("应删库行")
	}
	if len(admin.deleted) != 1 || admin.deleted[0] != "sk-x" {
		t.Errorf("应删上游 key sk-x, 实际 %+v", admin.deleted)
	}
	if v, _, _ := cache.Get(context.Background(), "u1"); v != "" {
		t.Errorf("应清缓存")
	}
}

// 空 userUUID 防御。
func TestGetOrCreate_EmptyUUID(t *testing.T) {
	svc, _, _, _ := newSvc()
	if _, err := svc.GetOrCreateVirtualKey(context.Background(), ""); err == nil {
		t.Fatal("空 uuid 应返回错误")
	}
}
