package clawhub

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSkillsClient 是 SkillsClient 的最小内存假实现（仅覆盖被缓存的两个方法）。
type fakeSkillsClient struct {
	listCalls atomic.Int64
	getCalls  atomic.Int64
}

func (f *fakeSkillsClient) ListSkills(context.Context, SkillListParams) (*SkillPage, error) {
	f.listCalls.Add(1)
	return &SkillPage{Items: []SkillListItem{{Slug: "ws"}}}, nil
}

func (f *fakeSkillsClient) GetSkill(_ context.Context, slug string) (*SkillDetail, error) {
	f.getCalls.Add(1)
	return &SkillDetail{Skill: SkillInfo{Slug: slug, DisplayName: slug}}, nil
}

func (f *fakeSkillsClient) ListSkillVersions(context.Context, string, PageParams) (*SkillVersionPage, error) {
	panic("not expected")
}
func (f *fakeSkillsClient) GetSkillVersion(context.Context, string, string) (*SkillVersionDetail, error) {
	panic("not expected")
}
func (f *fakeSkillsClient) ResolveSkill(context.Context, string, string) (*ResolveResult, error) {
	panic("not expected")
}
func (f *fakeSkillsClient) SkillDownloadStreamURL(string, string) string { panic("not expected") }
func (f *fakeSkillsClient) SecurityVerdicts(context.Context, []VerdictRequestItem) (*SecurityVerdictResult, error) {
	panic("not expected")
}

// 命中：同一参数二次调用 ListSkills，inner 仅一次。
func TestCachingSkills_ListHitsAfterFirstCall(t *testing.T) {
	rdb, _ := newTestCacheRDB(t)
	fake := &fakeSkillsClient{}
	c := NewCachingSkillsClient(fake, rdb, 5*time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := c.ListSkills(context.Background(), SkillListParams{Limit: 20, Sort: "updated"}); err != nil {
			t.Fatalf("第%d次 ListSkills 失败: %v", i, err)
		}
	}
	if got := fake.listCalls.Load(); got != 1 {
		t.Errorf("inner ListSkills 调用次数 = %d, 期望 1", got)
	}
}

// 命中：同一 slug 二次 GetSkill，inner 仅一次，且 key 带 gw:hub: 前缀。
func TestCachingSkills_DetailHitsAndKeyPrefix(t *testing.T) {
	rdb, mr := newTestCacheRDB(t)
	fake := &fakeSkillsClient{}
	c := NewCachingSkillsClient(fake, rdb, 5*time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := c.GetSkill(context.Background(), "web-search"); err != nil {
			t.Fatalf("第%d次 GetSkill 失败: %v", i, err)
		}
	}
	if got := fake.getCalls.Load(); got != 1 {
		t.Errorf("inner GetSkill 调用次数 = %d, 期望 1", got)
	}
	keys := mr.Keys()
	if len(keys) != 1 || keys[0] != "gw:hub:skill:web-search" {
		t.Errorf("Redis key = %v, 期望 [gw:hub:skill:web-search]", keys)
	}
}
