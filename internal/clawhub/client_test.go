package clawhub_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// 正路：ListPackages 解析 ClawHub /packages 响应，并把对外查询参数透传为 query。
func TestListPackages_HappyPath(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items": [
				{
					"name": "@vulture/notion-sync",
					"displayName": "Notion Sync",
					"pluginCategory": {"id": "ecommerce", "label": "电商与市场"},
					"family": "code-plugin",
					"channel": "community",
					"isOfficial": false,
					"latestVersion": "0.4.1",
					"executesCode": true,
					"scanStatus": "clean"
				}
			],
			"nextCursor": "cursor-2"
		}`))
	}))
	defer srv.Close()

	c := clawhub.NewHTTPClient(srv.URL, srv.Client())
	page, err := c.ListPackages(context.Background(), clawhub.ListParams{
		Limit:    20,
		Sort:     "trending",
		Family:   "code-plugin",
		Channel:  "community",
		Category: "ecommerce",
	})
	if err != nil {
		t.Fatalf("ListPackages 失败: %v", err)
	}

	if gotPath != "/packages" {
		t.Errorf("请求路径 = %q, 期望 /packages", gotPath)
	}
	for _, want := range []string{"limit=20", "sort=trending", "family=code-plugin", "channel=community", "category=ecommerce"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q 缺少 %q", gotQuery, want)
		}
	}

	if len(page.Items) != 1 {
		t.Fatalf("items 数 = %d, 期望 1", len(page.Items))
	}
	item := page.Items[0]
	if item.Name != "@vulture/notion-sync" {
		t.Errorf("name = %q", item.Name)
	}
	if item.PluginCategory == nil || item.PluginCategory.ID != "ecommerce" {
		t.Errorf("pluginCategory 解析错误: %+v", item.PluginCategory)
	}
	if item.ExecutesCode == nil || !*item.ExecutesCode {
		t.Errorf("executesCode 期望 true, 实际 %v", item.ExecutesCode)
	}
	if page.NextCursor == nil || *page.NextCursor != "cursor-2" {
		t.Errorf("nextCursor = %v, 期望 cursor-2", page.NextCursor)
	}
}

// 空参数：limit<=0 与空字符串字段不下发 query。
func TestListPackages_OmitsEmptyParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"items": [], "nextCursor": null}`))
	}))
	defer srv.Close()

	c := clawhub.NewHTTPClient(srv.URL, srv.Client())
	page, err := c.ListPackages(context.Background(), clawhub.ListParams{})
	if err != nil {
		t.Fatalf("ListPackages 失败: %v", err)
	}
	if gotQuery != "" {
		t.Errorf("空参数不应产生 query, 实际 %q", gotQuery)
	}
	if len(page.Items) != 0 || page.NextCursor != nil {
		t.Errorf("空页解析错误: items=%d nextCursor=%v", len(page.Items), page.NextCursor)
	}
}

// 错误路：ClawHub 非 2xx 返回 *clawhub.Error，携带状态码与错误体。
func TestListPackages_MapsErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "not_found", "message": "no such filter"}`))
	}))
	defer srv.Close()

	c := clawhub.NewHTTPClient(srv.URL, srv.Client())
	_, err := c.ListPackages(context.Background(), clawhub.ListParams{})
	if err == nil {
		t.Fatal("期望错误, 实际 nil")
	}
	hubErr, ok := err.(*clawhub.Error)
	if !ok {
		t.Fatalf("错误类型 = %T, 期望 *clawhub.Error", err)
	}
	if hubErr.Status != http.StatusNotFound || hubErr.Code != "not_found" {
		t.Errorf("error 映射错误: status=%d code=%q", hubErr.Status, hubErr.Code)
	}
}

// 传输失败（ClawHub 不可达）返回非 *clawhub.Error 的普通错误，由 handler 收敛为 502。
func TestListPackages_TransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // 立即关闭使其不可达

	c := clawhub.NewHTTPClient(url, &http.Client{})
	_, err := c.ListPackages(context.Background(), clawhub.ListParams{})
	if err == nil {
		t.Fatal("期望传输错误, 实际 nil")
	}
	if _, ok := err.(*clawhub.Error); ok {
		t.Error("传输失败不应是 *clawhub.Error")
	}
}
