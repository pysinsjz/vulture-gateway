package router_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/pysinsjz/vulture-gateway/config"
)

// stubClawHub 返回一个桩 ClawHub 服务器与其被命中次数计数器。
func stubClawHub(t *testing.T, status int, body string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/packages" {
			t.Errorf("ClawHub 被请求路径 = %q, 期望 /packages", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("ClawHub 不应收到鉴权头, 实际 %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func withClawHub(url string) func(*config.Configuration) {
	return func(cfg *config.Configuration) { cfg.ClawHub.BaseURL = url }
}

// 正路：合法 Bearer → 200，数据经 ClawHub /packages 翻译（pluginCategory → category）。
func TestListPlugins_HappyPath(t *testing.T) {
	srv, hits := stubClawHub(t, http.StatusOK, `{
		"items": [
			{"name": "@vulture/notion-sync", "displayName": "Notion Sync",
			 "pluginCategory": {"id": "ecommerce", "label": "电商与市场"},
			 "family": "code-plugin", "channel": "community", "isOfficial": false,
			 "latestVersion": "0.4.1", "executesCode": true, "scanStatus": "clean"}
		],
		"nextCursor": "cursor-2"
	}`)
	e := newTestEngine(t, withClawHub(srv.URL))
	token := issueViaScaffold(t, e, "user-9", "dev-9")

	rec := do(t, e, http.MethodGet, "/api/v1/plugins?limit=20&sort=trending&category=ecommerce", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("ClawHub 命中次数 = %d, 期望 1", atomic.LoadInt32(hits))
	}

	var page struct {
		Items []struct {
			Name     string `json:"name"`
			Category *struct {
				ID    string `json:"id"`
				Label string `json:"label"`
			} `json:"category"`
			ScanStatus string `json:"scanStatus"`
		} `json:"items"`
		NextCursor *string `json:"nextCursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("解析 Page 响应失败: %v (body=%s)", err, rec.Body.String())
	}
	if len(page.Items) != 1 {
		t.Fatalf("items 数 = %d, 期望 1", len(page.Items))
	}
	if page.Items[0].Category == nil || page.Items[0].Category.ID != "ecommerce" {
		t.Errorf("category 翻译错误: %+v", page.Items[0].Category)
	}
	if page.Items[0].ScanStatus != "clean" {
		t.Errorf("scanStatus 透传错误: %q", page.Items[0].ScanStatus)
	}
	if page.NextCursor == nil || *page.NextCursor != "cursor-2" {
		t.Errorf("nextCursor = %v, 期望 cursor-2", page.NextCursor)
	}
}

// 鉴权负路：缺失/失效 token → 401 ApiError，且不触达 ClawHub。
func TestListPlugins_UnauthorizedDoesNotReachClawHub(t *testing.T) {
	srv, hits := stubClawHub(t, http.StatusOK, `{"items": [], "nextCursor": null}`)
	e := newTestEngine(t, withClawHub(srv.URL))

	cases := map[string]string{
		"缺失":  "",
		"垃圾串": "garbage.token.value",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, e, http.MethodGet, "/api/v1/plugins", token, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("期望 401, 实际 %d: %s", rec.Code, rec.Body.String())
			}
			assertApiError(t, rec)
		})
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Errorf("鉴权失败不应触达 ClawHub, 命中 %d 次", atomic.LoadInt32(hits))
	}
}

// ClawHub 返回 4xx → 透传状态码 + ApiError（ADR-0011）。
func TestListPlugins_ClawHubClientError(t *testing.T) {
	srv, _ := stubClawHub(t, http.StatusNotFound, `{"error": "not_found", "message": "no such filter"}`)
	e := newTestEngine(t, withClawHub(srv.URL))
	token := issueViaScaffold(t, e, "user-9", "dev-9")

	rec := do(t, e, http.MethodGet, "/api/v1/plugins?category=ghost", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("期望透传 404, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertApiError(t, rec)
}

// ClawHub 不可达 → 502 upstream_unavailable（ApiError）。
func TestListPlugins_ClawHubUnreachable(t *testing.T) {
	e := newTestEngine(t, withClawHub("http://127.0.0.1:1"))
	token := issueViaScaffold(t, e, "user-9", "dev-9")

	rec := do(t, e, http.MethodGet, "/api/v1/plugins", token, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertApiError(t, rec)
}

// limit 非法 → 400 ApiError，请求在网关侧即被拒（不触达 ClawHub）。
func TestListPlugins_InvalidLimit(t *testing.T) {
	srv, hits := stubClawHub(t, http.StatusOK, `{"items": [], "nextCursor": null}`)
	e := newTestEngine(t, withClawHub(srv.URL))
	token := issueViaScaffold(t, e, "user-9", "dev-9")

	rec := do(t, e, http.MethodGet, "/api/v1/plugins?limit=abc", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("期望 400, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertApiError(t, rec)
	if atomic.LoadInt32(hits) != 0 {
		t.Errorf("参数非法不应触达 ClawHub, 命中 %d 次", atomic.LoadInt32(hits))
	}
}
