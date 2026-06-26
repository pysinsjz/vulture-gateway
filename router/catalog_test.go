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
// routes 在结构体上暴露，便于创建后回填依赖 srv.URL 的路由（如下载代理的流式端点）；
// 回填须在发起任何请求前完成，故无并发读写。
type catalogStub struct {
	srv    *httptest.Server
	routes map[string]func() (int, string)
	hits   int32
}

// newCatalogStub 装配一个路由表驱动的桩 ClawHub；断言不收到鉴权头（纯内网）。
func newCatalogStub(t *testing.T, routes map[string]func() (int, string)) *catalogStub {
	t.Helper()
	s := &catalogStub{routes: routes}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("ClawHub 不应收到鉴权头, 实际 %q", r.Header.Get("Authorization"))
		}
		if fn, ok := s.routes[r.URL.Path]; ok {
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

// 分类端点正路（§3.1b，网关派生）：/skills/categories、/plugins/categories 落到分类 handler，
// 聚合上游列表端点（/skills、/packages）而非被当作 slug/name 查单个制品。
// 这正是原 bug 的回归点：曾经 GET /api/v1/skills/categories 落到 :slug 通配 → 上游按 skill 查
// categories → 404 "Skill not found"。
func TestCatalog_CategoriesEndpoints(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills": ok(`{"items":[
			{"slug":"a","category":{"id":"research","label":"市场调研"}},
			{"slug":"b","category":{"id":"research","label":"市场调研"}},
			{"slug":"c"}
		],"nextCursor":null}`),
		"/packages": ok(`{"items":[
			{"name":"@v/a","pluginCategory":{"id":"ecommerce","label":"电商与市场"}},
			{"name":"@v/b","pluginCategory":{"id":"marketing","label":"营销与广告"}}
		],"nextCursor":null}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	type catResp struct {
		Categories []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			Count int    `json:"count"`
		} `json:"categories"`
	}

	// skill 分类：research(2) + 其他(1，c 无分类)。
	rec := do(t, e, http.MethodGet, "/api/v1/skills/categories", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("skill categories 期望 200（非落到 :slug → 404），实际 %d: %s", rec.Code, rec.Body.String())
	}
	var sc catResp
	if err := json.Unmarshal(rec.Body.Bytes(), &sc); err != nil {
		t.Fatalf("解析 skill categories 失败: %v (%s)", err, rec.Body.String())
	}
	if len(sc.Categories) != 2 || sc.Categories[0].ID != "research" || sc.Categories[0].Count != 2 {
		t.Errorf("skill 分类聚合错误: %+v", sc.Categories)
	}
	if last := sc.Categories[len(sc.Categories)-1]; last.ID != "other" || last.Count != 1 {
		t.Errorf("未分类应归末位『其他』(count=1), 实际 %+v", last)
	}

	// plugin 分类：ecommerce(1) + marketing(1)，无未分类桶。
	rec = do(t, e, http.MethodGet, "/api/v1/plugins/categories", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin categories 期望 200（非落到 :name → 404），实际 %d: %s", rec.Code, rec.Body.String())
	}
	var pc catResp
	if err := json.Unmarshal(rec.Body.Bytes(), &pc); err != nil {
		t.Fatalf("解析 plugin categories 失败: %v (%s)", err, rec.Body.String())
	}
	if len(pc.Categories) != 2 || pc.Categories[0].ID != "ecommerce" || pc.Categories[1].ID != "marketing" {
		t.Errorf("plugin 分类聚合错误: %+v", pc.Categories)
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

// 下载正路（interim 路线 A）：网关直接反代 ClawHub 流式端点，把字节透传回桌面端
// （非 302，因桌面端到不了内网 ClawHub）。skill 走顶层 /download，plugin 走 /packages/{name}/download，
// npm-pack 走 /packages/{name}/versions/{v}/artifact/download。
func TestDownload_ProxiesBytes(t *testing.T) {
	const skillBytes = "SKILL-ZIP-BYTES"
	const pluginBytes = "PLUGIN-ZIP-BYTES"
	const artifactBytes = "ARTIFACT-TGZ-BYTES"
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/download":               func() (int, string) { return http.StatusOK, skillBytes },
		"/packages/@v/x/download": func() (int, string) { return http.StatusOK, pluginBytes },
		"/packages/@v/x/versions/1.2.0/artifact/download": func() (int, string) { return http.StatusOK, artifactBytes },
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	cases := []struct {
		name, path, wantBytes string
	}{
		{"skill", "/api/v1/skills/gifgrep/download?version=1.2.0", skillBytes},
		{"plugin-legacy", "/api/v1/plugins/@v%2Fx/download?version=1.2.0", pluginBytes},
		{"plugin-npm", "/api/v1/plugins/@v%2Fx/versions/1.2.0/artifact/download", artifactBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, e, http.MethodGet, tc.path, token, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
			}
			// 网关反代：响应体即制品字节。
			if got := rec.Body.String(); got != tc.wantBytes {
				t.Errorf("响应体 = %q, 期望制品字节 %q", got, tc.wantBytes)
			}
		})
	}
}

// 安全门阻断：ClawHub 流式端点 403(blocked) → 网关反代时原样透传 403 + body，拿不到 Location。
func TestDownload_SecurityGateBlocks(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/download": func() (int, string) {
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

// pending：ClawHub 流式端点 423 → 网关反代时原样透传 423（与 malicious 的 403 区分）。
func TestDownload_PendingDistinctFromMalicious(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/packages/@v/x/download": func() (int, string) {
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

// ClawHub 流式端点 5xx（注册中心自身故障）→ 网关收敛为 502，不暴露上游故障细节。
func TestDownload_UpstreamServerErrorBecomes502(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/download": func() (int, string) {
			return http.StatusInternalServerError, `boom`
		},
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	rec := do(t, e, http.MethodGet, "/api/v1/skills/gifgrep/download", token, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("上游 5xx 期望收敛 502, 实际 %d: %s", rec.Code, rec.Body.String())
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
