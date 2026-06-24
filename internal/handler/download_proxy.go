package handler

import (
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/pkg/apierror"
)

// downloadProxy 把内网 ClawHub 的制品流式端点反向代理给桌面端（interim 路线 A，见
// docs/flows/clawhub-integration.md「下载链路」）。
//
// 背景：ClawHub 纯内网、桌面端只能到网关。当前 artifact 字节由 ClawHub 流式端点直吐
// （GET /api/v1/download、/packages/{name}/download、/packages/{name}/versions/{v}/artifact/download），
// 桌面端不可达。故网关直接反代这些流式端点：服务端 GET（内网可达）后把状态码 + 白名单响应头 + 字节
// 透传回桌面端。安全门由 ClawHub 在流式端点内强制（getReleaseSecurityBlock / getPublicSkillFileAccessBlock
// → 403/410/451 等业务码），反代时原样透传。待 ClawHub 落地路线 B（MinIO 真预签名、公网可达带 TTL）后，
// 流式端点改为 302 跳 MinIO、网关原样透传该 302，桌面端直连存储取字节——迁移对网关透明。
//
// 注：client 默认跟随 3xx（处理 npm-pack 内部 307 到 tarball 字节源）；路线 B 切换时若需把 302 透传给
// 桌面端而非服务端跟随，再调整 CheckRedirect。
type downloadProxy struct {
	client *http.Client
}

// NewDownloadProxy 构造下载代理。client 为 nil 时退回无超时客户端（由请求 ctx 约束生命周期）。
func NewDownloadProxy(client *http.Client) *downloadProxy {
	if client == nil {
		client = &http.Client{}
	}
	return &downloadProxy{client: client}
}

// proxySafeHeaders 是从下载源透传给桌面端的响应头白名单（避免回传 Set-Cookie 等敏感/无关头）。
// X-ClawHub-Artifact-Sha256 供桌面端做完整性自校验（与版本详情 artifact.sha256 一致）。
var proxySafeHeaders = []string{
	"Content-Type",
	"Content-Length",
	"Content-Disposition",
	"ETag",
	"Last-Modified",
	"Cache-Control",
	"Accept-Ranges",
	"Location",
	"X-ClawHub-Artifact-Sha256",
}

// stream 反代 ClawHub 流式端点：服务端 GET 后把状态码 + 白名单响应头 + 字节透传回桌面端。
//   - 地址非法 / 传输失败 / 上游 5xx → 收敛为 502，不暴露畸形地址或上游故障细节。
//   - 上游 2xx（字节）、3xx（路线 B 的 302 跳存储）、4xx（安全门 403/410/451、404）→ 原样透传状态码 + body，
//     让桌面端拿到 ClawHub 的真实业务裁决（ADR-0011）。
func (p *downloadProxy) stream(c *gin.Context, rawURL string) {
	if !isAbsoluteHTTPURL(rawURL) {
		apierror.Abort(c, http.StatusBadGateway, "upstream_unavailable", "注册中心返回了无效的下载地址")
		return
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		apierror.Abort(c, http.StatusBadGateway, "upstream_unavailable", "构造下载请求失败")
		return
	}

	resp, err := p.client.Do(req)
	if err != nil {
		apierror.Abort(c, http.StatusBadGateway, "upstream_unavailable", "拉取制品失败")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 上游 5xx 是注册中心自身故障，对桌面端收敛为 502；其余（含安全门 4xx）原样透传。
	if resp.StatusCode >= 500 {
		apierror.Abort(c, http.StatusBadGateway, "upstream_unavailable", "下载源返回异常状态")
		return
	}

	for _, h := range proxySafeHeaders {
		if v := resp.Header.Get(h); v != "" {
			c.Header(h, v)
		}
	}
	c.Status(resp.StatusCode)
	_, _ = io.Copy(c.Writer, resp.Body)
}

// isAbsoluteHTTPURL 判定字符串为带 host 的绝对 http/https URL。
func isAbsoluteHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}
