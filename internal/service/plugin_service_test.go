package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeClawHub 是 clawhub.Client 的内存 fake，便于在不触网的情况下单测翻译逻辑。
type fakeClawHub struct {
	gotParams clawhub.ListParams
	page      *clawhub.PackagePage
	err       error
}

func (f *fakeClawHub) ListPackages(_ context.Context, params clawhub.ListParams) (*clawhub.PackagePage, error) {
	f.gotParams = params
	return f.page, f.err
}

func boolPtr(b bool) *bool { return &b }

func strPtr(s string) *string { return &s }

// 翻译正路：pluginCategory → category，其余字段透传，分页游标保留。
func TestListPlugins_TranslatesPackages(t *testing.T) {
	fake := &fakeClawHub{
		page: &clawhub.PackagePage{
			Items: []clawhub.PackageListItem{
				{
					Name:           "@vulture/notion-sync",
					DisplayName:    "Notion Sync",
					Summary:        "同步 Notion",
					PluginCategory: &clawhub.Category{ID: "ecommerce", Label: "电商与市场"},
					Family:         "code-plugin",
					Channel:        "community",
					IsOfficial:     false,
					LatestVersion:  "0.4.1",
					CapabilityTags: []string{"executes-code"},
					ExecutesCode:   boolPtr(true),
					ScanStatus:     "clean",
				},
			},
			NextCursor: strPtr("cursor-2"),
		},
	}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPlugins(context.Background(), service.PluginListParams{Limit: 20, Sort: "trending", Category: "ecommerce"})
	if err != nil {
		t.Fatalf("ListPlugins 失败: %v", err)
	}

	// 对外查询参数透传到 ClawHub。
	if fake.gotParams.Limit != 20 || fake.gotParams.Sort != "trending" || fake.gotParams.Category != "ecommerce" {
		t.Errorf("透传参数错误: %+v", fake.gotParams)
	}

	if len(page.Items) != 1 {
		t.Fatalf("items 数 = %d, 期望 1", len(page.Items))
	}
	item := page.Items[0]
	if item.Category == nil || item.Category.ID != "ecommerce" || item.Category.Label != "电商与市场" {
		t.Errorf("category 翻译错误: %+v", item.Category)
	}
	if item.Name != "@vulture/notion-sync" || item.LatestVersion != "0.4.1" || item.ScanStatus != "clean" {
		t.Errorf("字段透传错误: %+v", item)
	}
	if item.ExecutesCode == nil || !*item.ExecutesCode {
		t.Errorf("executesCode 透传错误: %v", item.ExecutesCode)
	}
	if page.NextCursor == nil || *page.NextCursor != "cursor-2" {
		t.Errorf("nextCursor 保留错误: %v", page.NextCursor)
	}
}

// 无分类的制品翻译为 category=null。
func TestListPlugins_NilCategory(t *testing.T) {
	fake := &fakeClawHub{
		page: &clawhub.PackagePage{
			Items: []clawhub.PackageListItem{{Name: "x", DisplayName: "X", PluginCategory: nil}},
		},
	}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPlugins(context.Background(), service.PluginListParams{})
	if err != nil {
		t.Fatalf("ListPlugins 失败: %v", err)
	}
	if page.Items[0].Category != nil {
		t.Errorf("无分类应为 nil, 实际 %+v", page.Items[0].Category)
	}
}

// 空列表翻译为空 items + nil 游标。
func TestListPlugins_EmptyPage(t *testing.T) {
	fake := &fakeClawHub{page: &clawhub.PackagePage{Items: nil, NextCursor: nil}}
	svc := service.NewPluginService(fake)

	page, err := svc.ListPlugins(context.Background(), service.PluginListParams{})
	if err != nil {
		t.Fatalf("ListPlugins 失败: %v", err)
	}
	if len(page.Items) != 0 {
		t.Errorf("items 应为空, 实际 %d", len(page.Items))
	}
	if page.NextCursor != nil {
		t.Errorf("nextCursor 应为 nil, 实际 %v", page.NextCursor)
	}
}

// ClawHub 错误原样上抛，由 handler 重映射。
func TestListPlugins_PropagatesError(t *testing.T) {
	hubErr := &clawhub.Error{Status: 503, Code: "unavailable"}
	fake := &fakeClawHub{err: hubErr}
	svc := service.NewPluginService(fake)

	_, err := svc.ListPlugins(context.Background(), service.PluginListParams{})
	if !errors.Is(err, hubErr) {
		t.Errorf("应原样上抛 ClawHub 错误, 实际 %v", err)
	}
}
