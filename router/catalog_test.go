package router_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

// catalogStub 是按路径路由的桩 ClawHub（覆盖 skill/plugin 全部 #20 端点）。
type catalogStub struct {
	srv  *httptest.Server
	hits int32
}

// newCatalogStub 装配一个路由表驱动的桩 ClawHub；断言不收到鉴权头（纯内网）。
func newCatalogStub(t *testing.T, routes map[string]func() (int, string)) *catalogStub {
	t.Helper()
	s := &catalogStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("ClawHub 不应收到鉴权头, 实际 %q", r.Header.Get("Authorization"))
		}
		if fn, ok := routes[r.URL.Path]; ok {
			status, body := fn()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"no route"}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func ok(body string) func() (int, string) {
	return func() (int, string) { return http.StatusOK, body }
}

// doWithHeaders 发请求并附加自定义头（兼容过滤用）。
func doWithHeaders(t *testing.T, e *gin.Engine, method, path, bearer string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// skill 列表正路：category 透传 + X-Platform 平台过滤（metadata.systems）。
func TestSkills_ListAndPlatformFilter(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills": ok(`{"items":[
			{"slug":"mac","displayName":"Mac","category":{"id":"research","label":"市场调研"},"tags":{"latest":"1.0.0"},"metadata":{"systems":["darwin-arm64"]}},
			{"slug":"win","displayName":"Win","tags":{},"metadata":{"systems":["win32-x64"]}}
		],"nextCursor":null}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := doWithHeaders(t, e, http.MethodGet, "/api/v1/skills?sort=trending", token, map[string]string{"X-Platform": "darwin-arm64"})
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []struct {
			Slug     string `json:"slug"`
			Category *struct {
				ID string `json:"id"`
			} `json:"category"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("解析失败: %v (%s)", err, rec.Body.String())
	}
	if len(page.Items) != 1 || page.Items[0].Slug != "mac" {
		t.Fatalf("平台过滤错误，期望仅 mac, 实际 %+v", page.Items)
	}
	if page.Items[0].Category == nil || page.Items[0].Category.ID != "research" {
		t.Errorf("category 透传错误: %+v", page.Items[0].Category)
	}
}

// skill 详情 / 版本历史 / 指定版本（含 artifact.sha256）正路。
func TestSkills_DetailVersionsAndVersion(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills/gifgrep":                ok(`{"skill":{"slug":"gifgrep","displayName":"GifGrep","tags":{"latest":"1.2.0"}},"latestVersion":{"version":"1.2.0","changelog":"c","license":"MIT"},"metadata":null}`),
		"/skills/gifgrep/versions":       ok(`{"items":[{"version":"1.2.0","createdAt":2,"changelog":"c","changelogSource":"user"}],"nextCursor":"c2"}`),
		"/skills/gifgrep/versions/1.2.0": ok(`{"skill":{"slug":"gifgrep","displayName":"GifGrep"},"version":{"version":"1.2.0","files":[{"path":"SKILL.md","size":5,"sha256":"f1"}],"artifact":{"sha256":"archive-sha","size":1024}}}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/skills/gifgrep", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}

	rec = do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/versions", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("versions 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}

	rec = do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/versions/1.2.0", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("version 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var vd struct {
		Version struct {
			Artifact struct {
				SHA256 string `json:"sha256"`
			} `json:"artifact"`
		} `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &vd); err != nil {
		t.Fatalf("解析 version 失败: %v", err)
	}
	if vd.Version.Artifact.SHA256 != "archive-sha" {
		t.Errorf("artifact.sha256 翻译错误: %q", vd.Version.Artifact.SHA256)
	}
}

// resolve 正路：hash 透传，match==null 供客户端辨因。
func TestSkills_ResolveMatchNull(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills/gifgrep/resolve": ok(`{"slug":"gifgrep","match":null,"latestVersion":{"version":"1.3.0"}}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/resolve?hash="+hash, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var r struct {
		Match         *struct{ Version string } `json:"match"`
		LatestVersion *struct{ Version string } `json:"latestVersion"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("解析 resolve 失败: %v", err)
	}
	if r.Match != nil || r.LatestVersion == nil {
		t.Errorf("resolve 形态错误: %s", rec.Body.String())
	}
}

// resolve 非法 hash → 400，在网关侧即被拒（不触达 ClawHub）。
func TestSkills_ResolveInvalidHash(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/resolve?hash=xyz", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 hash 期望 400, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertApiError(t, rec)
	if atomic.LoadInt32(&stub.hits) != 0 {
		t.Errorf("非法 hash 不应触达 ClawHub, 命中 %d 次", atomic.LoadInt32(&stub.hits))
	}
}

// plugin 详情 / 指定版本正路（pluginCategory→category，artifact）。
func TestPlugins_DetailAndVersion(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/packages/@v/x":                ok(`{"package":{"name":"@v/x","displayName":"X","family":"code-plugin","channel":"official","isOfficial":true},"pluginCategory":{"id":"marketing","label":"营销"},"latestVersion":{"version":"1.2.0","createdAt":1,"changelog":"c"}}`),
		"/packages/@v/x/releases/1.2.0": ok(`{"package":{"name":"@v/x","displayName":"X","family":"code-plugin"},"version":{"version":"1.2.0","distTags":["latest"],"artifact":{"kind":"npm-pack","sha256":"deadbeef","size":2048}}}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	// scoped 包名 @v/x 须 URL 编码为 @v%2Fx（见 router.UseRawPath）。
	rec := do(t, e, http.MethodGet, "/api/v1/plugins/@v%2Fx", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin detail 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var pd struct {
		Package struct {
			Category *struct{ ID string } `json:"category"`
		} `json:"package"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("解析 plugin detail 失败: %v", err)
	}
	if pd.Package.Category == nil || pd.Package.Category.ID != "marketing" {
		t.Errorf("category 翻译错误: %+v", pd.Package.Category)
	}

	rec = do(t, e, http.MethodGet, "/api/v1/plugins/@v%2Fx/versions/1.2.0", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin version 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

// pending / 软删除：ClawHub 423/410 经网关透传（与 malicious 的 403 区分）。
func TestCatalog_PassesThroughBusinessStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"pending-423", http.StatusLocked},
		{"conflict-409", http.StatusConflict},
		{"gone-410", http.StatusGone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.status
			stub := newCatalogStub(t, map[string]func() (int, string){
				"/skills/gifgrep/versions/9.9.9": func() (int, string) {
					return status, `{"error":"unavailable","message":"扫描中"}`
				},
			})
			e := newTestEngine(t, withClawHub(stub.srv.URL))
			token := issueViaScaffold(t, e, "u", "d")

			rec := do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/versions/9.9.9", token, nil)
			if rec.Code != status {
				t.Fatalf("期望透传 %d, 实际 %d: %s", status, rec.Code, rec.Body.String())
			}
			assertApiError(t, rec)
		})
	}
}

// 下载正路：skill / plugin(legacy-zip) / plugin(npm-pack) 均 302 跳短时效 R2 URL，字节不经网关。
func TestDownload_RedirectsToSignedURL(t *testing.T) {
	const skillURL = "https://r2.example.com/gifgrep.zip?sig=s1"
	const pluginURL = "https://r2.example.com/x.zip?sig=p1"
	const artifactURL = "https://r2.example.com/x.tgz?sig=a1"
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills/gifgrep/download-url":               ok(`{"url":"` + skillURL + `"}`),
		"/packages/@v/x/download-url":                ok(`{"url":"` + pluginURL + `"}`),
		"/packages/@v/x/releases/1.2.0/artifact-url": ok(`{"url":"` + artifactURL + `"}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	cases := []struct {
		name, path, wantURL string
	}{
		{"skill", "/api/v1/skills/gifgrep/download?version=1.2.0", skillURL},
		{"plugin-legacy", "/api/v1/plugins/@v%2Fx/download?version=1.2.0", pluginURL},
		{"plugin-npm", "/api/v1/plugins/@v%2Fx/versions/1.2.0/artifact/download", artifactURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, e, http.MethodGet, tc.path, token, nil)
			if rec.Code != http.StatusFound {
				t.Fatalf("期望 302, 实际 %d: %s", rec.Code, rec.Body.String())
			}
			if loc := rec.Header().Get("Location"); loc != tc.wantURL {
				t.Errorf("Location = %q, 期望 %q", loc, tc.wantURL)
			}
			// 字节不经网关：响应体不含制品内容（仅 302 跳转）。
			if len(rec.Body.Bytes()) > 256 {
				t.Errorf("响应体疑似夹带制品字节, 长度 %d", len(rec.Body.Bytes()))
			}
		})
	}
}

// 安全门阻断：ClawHub 403(blocked) → 网关透传 403 ApiError，拿不到 Location。
func TestDownload_SecurityGateBlocks(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills/evil/download-url": func() (int, string) {
			return http.StatusForbidden, `{"error":"blocked","message":"scan:malicious"}`
		},
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/skills/evil/download", token, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("期望 403, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Error("被阻断制品不应拿到 Location")
	}
	var body struct{ Error string }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error != "blocked" {
		t.Errorf("error code = %q, 期望 blocked", body.Error)
	}
}

// pending：ClawHub 423 → 网关透传 423（与 malicious 的 403 区分）。
func TestDownload_PendingDistinctFromMalicious(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/packages/@v/x/download-url": func() (int, string) {
			return http.StatusLocked, `{"error":"pending","message":"扫描中"}`
		},
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/plugins/@v%2Fx/download", token, nil)
	if rec.Code != http.StatusLocked {
		t.Fatalf("pending 期望透传 423, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Error("pending 不应拿到 Location")
	}
}

// ClawHub 返回畸形下载地址 → 网关收敛为 502，不把无效地址作 Location 暴露。
func TestDownload_InvalidURLFromClawHub(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills/gifgrep/download-url": ok(`{"url":"not-a-valid-url"}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/download", token, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("无效地址期望 502, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Error("无效地址不应作 Location 暴露")
	}
	assertApiError(t, rec)
}

// 鉴权负路：skill 端点缺 Bearer → 401，不触达 ClawHub。
func TestSkills_UnauthorizedDoesNotReachClawHub(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){"/skills": ok(`{"items":[],"nextCursor":null}`)})
	e := newTestEngine(t, withClawHub(stub.srv.URL))

	rec := do(t, e, http.MethodGet, "/api/v1/skills", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401, 实际 %d", rec.Code)
	}
	assertApiError(t, rec)
	if atomic.LoadInt32(&stub.hits) != 0 {
		t.Errorf("鉴权失败不应触达 ClawHub, 命中 %d 次", atomic.LoadInt32(&stub.hits))
	}
}
