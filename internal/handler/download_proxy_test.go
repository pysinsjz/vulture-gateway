package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// streamRec 用 downloadProxy.stream 跑一次请求，返回 recorder。
func streamRec(t *testing.T, p *downloadProxy, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/dl", nil)
	p.stream(c, rawURL)
	return rec
}

// 正路：拉取上游 2xx 字节并透传白名单响应头。
func TestDownloadProxy_StreamsBytesAndSafeHeaders(t *testing.T) {
	const payload = "ARTIFACT-BYTES"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="x.zip"`)
		w.Header().Set("Set-Cookie", "secret=1") // 不在白名单，应被剔除
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}))
	defer up.Close()

	rec := streamRec(t, NewDownloadProxy(up.Client()), up.URL)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", rec.Code)
	}
	if rec.Body.String() != payload {
		t.Errorf("body = %q, 期望 %q", rec.Body.String(), payload)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q, 期望 application/zip", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("Content-Disposition 应透传")
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("Set-Cookie 不在白名单, 不应透传")
	}
}

// 非法地址（非绝对 http URL）→ 502，不暴露给客户端。
func TestDownloadProxy_InvalidURL(t *testing.T) {
	for _, raw := range []string{"", "/relative/path", "ftp://x/y", "not a url"} {
		rec := streamRec(t, NewDownloadProxy(nil), raw)
		if rec.Code != http.StatusBadGateway {
			t.Errorf("url=%q 期望 502, 实际 %d", raw, rec.Code)
		}
	}
}

// 上游 5xx（注册中心自身故障）→ 收敛为 502，不把上游状态/细节透传。
func TestDownloadProxy_Upstream5xxBecomes502(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer up.Close()

	rec := streamRec(t, NewDownloadProxy(up.Client()), up.URL)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502, 实际 %d", rec.Code)
	}
}

// 上游 4xx（安全门 403/410/451、404）→ 原样透传状态码 + body，让桌面端拿到真实业务裁决。
func TestDownloadProxy_Upstream4xxPassesThrough(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusGone, http.StatusUnavailableForLegalReasons, http.StatusNotFound} {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"blocked"}`))
		}))
		rec := streamRec(t, NewDownloadProxy(up.Client()), up.URL)
		up.Close()
		if rec.Code != status {
			t.Errorf("上游 %d 应原样透传, 实际 %d", status, rec.Code)
		}
		if rec.Body.String() != `{"error":"blocked"}` {
			t.Errorf("上游 %d body 应透传, 实际 %q", status, rec.Body.String())
		}
	}
}

// 上游不可达（连接失败）→ 502。
func TestDownloadProxy_UpstreamUnreachable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := up.URL
	up.Close() // 立即关闭，制造连接失败

	rec := streamRec(t, NewDownloadProxy(nil), url)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502, 实际 %d", rec.Code)
	}
}
