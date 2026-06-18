package clawhub_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// muxStub 按路径路由的桩 ClawHub，记录最后命中的 path + query。
type muxStub struct {
	srv      *httptest.Server
	lastPath string
	lastRaw  string
}

func newMuxStub(t *testing.T, routes map[string]func() (int, string)) *muxStub {
	t.Helper()
	s := &muxStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lastPath = r.URL.Path
		s.lastRaw = r.URL.RawQuery
		if fn, ok := routes[r.URL.Path]; ok {
			status, body := fn()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func TestGetPackage_ParsesDetail(t *testing.T) {
	stub := newMuxStub(t, map[string]func() (int, string){
		"/packages/@v/x": func() (int, string) {
			return http.StatusOK, `{"package":{"name":"@v/x","displayName":"X","family":"code-plugin","channel":"official","isOfficial":true},"pluginCategory":{"id":"marketing","label":"营销"},"latestVersion":{"version":"1.2.0","createdAt":1,"changelog":"c"},"compatibility":{"minAppVersion":"1.0.0"}}`
		},
	})
	c := clawhub.NewHTTPClient(stub.srv.URL, stub.srv.Client())

	d, err := c.GetPackage(context.Background(), "@v/x")
	if err != nil {
		t.Fatalf("GetPackage 失败: %v", err)
	}
	if d.Package.Name != "@v/x" || d.LatestVersion == nil || d.LatestVersion.Version != "1.2.0" {
		t.Errorf("详情解析错误: %+v", d)
	}
	if d.Compatibility == nil || d.Compatibility.MinAppVersion != "1.0.0" {
		t.Errorf("compatibility 解析错误: %+v", d.Compatibility)
	}
}

func TestGetSkillVersion_ParsesArtifact(t *testing.T) {
	stub := newMuxStub(t, map[string]func() (int, string){
		"/skills/gifgrep/versions/1.2.0": func() (int, string) {
			return http.StatusOK, `{"skill":{"slug":"gifgrep","displayName":"GifGrep"},"version":{"version":"1.2.0","files":[{"path":"SKILL.md","size":5,"sha256":"f1"}],"artifact":{"sha256":"archive-sha","size":1024}}}`
		},
	})
	c := clawhub.NewHTTPClient(stub.srv.URL, stub.srv.Client())

	d, err := c.GetSkillVersion(context.Background(), "gifgrep", "1.2.0")
	if err != nil {
		t.Fatalf("GetSkillVersion 失败: %v", err)
	}
	if d.Version.Artifact.SHA256 != "archive-sha" || len(d.Version.Files) != 1 {
		t.Errorf("版本解析错误: %+v", d.Version)
	}
}

func TestResolveSkill_SendsHashQuery(t *testing.T) {
	stub := newMuxStub(t, map[string]func() (int, string){
		"/skills/gifgrep/resolve": func() (int, string) {
			return http.StatusOK, `{"slug":"gifgrep","match":null,"latestVersion":{"version":"1.3.0"}}`
		},
	})
	c := clawhub.NewHTTPClient(stub.srv.URL, stub.srv.Client())

	r, err := c.ResolveSkill(context.Background(), "gifgrep", "deadbeef")
	if err != nil {
		t.Fatalf("ResolveSkill 失败: %v", err)
	}
	if stub.lastRaw != "hash=deadbeef" {
		t.Errorf("hash query 未下发: %q", stub.lastRaw)
	}
	if r.Match != nil || r.LatestVersion == nil {
		t.Errorf("resolve 解析错误: %+v", r)
	}
}

// 下载 URL：解析 ClawHub 签发地址，version 作 query 下发。
func TestPackageDownloadURL_ParsesTarget(t *testing.T) {
	stub := newMuxStub(t, map[string]func() (int, string){
		"/packages/@v/x/download-url": func() (int, string) {
			return http.StatusOK, `{"url":"https://r2.example.com/x.zip?sig=abc"}`
		},
	})
	c := clawhub.NewHTTPClient(stub.srv.URL, stub.srv.Client())

	target, err := c.PackageDownloadURL(context.Background(), "@v/x", "1.2.0")
	if err != nil {
		t.Fatalf("PackageDownloadURL 失败: %v", err)
	}
	if target.URL != "https://r2.example.com/x.zip?sig=abc" {
		t.Errorf("url 解析错误: %q", target.URL)
	}
	if stub.lastRaw != "version=1.2.0" {
		t.Errorf("version query 未下发: %q", stub.lastRaw)
	}
}

// 安全门：ClawHub 下载端点 403（blocked）以 *clawhub.Error 携带状态码上抛。
func TestSkillDownloadURL_BlockedPassesThrough(t *testing.T) {
	stub := newMuxStub(t, map[string]func() (int, string){
		"/skills/evil/download-url": func() (int, string) {
			return http.StatusForbidden, `{"error":"blocked","message":"scan:malicious"}`
		},
	})
	c := clawhub.NewHTTPClient(stub.srv.URL, stub.srv.Client())

	_, err := c.SkillDownloadURL(context.Background(), "evil", "")
	hubErr, ok := err.(*clawhub.Error)
	if !ok {
		t.Fatalf("期望 *clawhub.Error, 实际 %T", err)
	}
	if hubErr.Status != http.StatusForbidden || hubErr.Code != "blocked" {
		t.Errorf("阻断错误映射错误: status=%d code=%q", hubErr.Status, hubErr.Code)
	}
}

// 业务状态码透传：410（软删除）/ 423（pending）以 *clawhub.Error 携带状态码上抛。
func TestGetSkillVersion_PassesThroughBusinessStatus(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusLocked, http.StatusConflict} {
		stub := newMuxStub(t, map[string]func() (int, string){
			"/skills/gifgrep/versions/9.9.9": func() (int, string) {
				return status, `{"error":"unavailable","message":"x"}`
			},
		})
		c := clawhub.NewHTTPClient(stub.srv.URL, stub.srv.Client())

		_, err := c.GetSkillVersion(context.Background(), "gifgrep", "9.9.9")
		hubErr, ok := err.(*clawhub.Error)
		if !ok {
			t.Fatalf("status=%d 期望 *clawhub.Error, 实际 %T", status, err)
		}
		if hubErr.Status != status {
			t.Errorf("status 透传错误: got %d 期望 %d", hubErr.Status, status)
		}
	}
}
