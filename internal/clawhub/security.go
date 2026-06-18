package clawhub

import (
	"context"
	"net/url"
)

// ─── skill 批量安全裁决（§3.6 security-verdicts）───

// VerdictRequestItem 是批量裁决请求的单项。
type VerdictRequestItem struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

// StaticScan 是确定性静态扫描结果（裁剪后唯一保留的自动扫描，#22）。
type StaticScan struct {
	Status      string   `json:"status"`
	ReasonCodes []string `json:"reasonCodes,omitempty"`
}

// SecuritySignals 是各扫描信号明细。
type SecuritySignals struct {
	StaticScan *StaticScan `json:"staticScan,omitempty"`
}

// SecurityStatus 是安全状态详情。放行一律以 VerdictItem.Decision 为准，本块仅供展示/日志。
type SecurityStatus struct {
	Status  string           `json:"status"` // clean | suspicious | malicious | pending
	Passed  bool             `json:"passed"`
	Signals *SecuritySignals `json:"signals,omitempty"`
}

// VerdictError 是裁决项查询失败时的错误。
type VerdictError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// VerdictItem 是单个 skill 版本的裁决结果。
type VerdictItem struct {
	OK               bool            `json:"ok"`
	Decision         string          `json:"decision"` // pass | fail
	Reasons          []string        `json:"reasons"`
	RequestedSlug    string          `json:"requestedSlug"`
	Slug             string          `json:"slug,omitempty"`
	DisplayName      string          `json:"displayName,omitempty"`
	RequestedVersion string          `json:"requestedVersion"`
	Version          string          `json:"version,omitempty"`
	Security         *SecurityStatus `json:"security"`
	Error            *VerdictError   `json:"error,omitempty"`
}

// SecurityVerdictResult 是批量裁决响应。
type SecurityVerdictResult struct {
	Schema string        `json:"schema"`
	Items  []VerdictItem `json:"items"`
}

// ─── plugin 单查安装阻断（§3.6 PluginTrust）───

// PluginTrustPkg 是 PluginTrust 的包标识。
type PluginTrustPkg struct {
	Name string `json:"name"`
}

// PluginTrustRelease 是 PluginTrust 的版本块。
type PluginTrustRelease struct {
	Version        string `json:"version"`
	ArtifactSha256 string `json:"artifactSha256"`
}

// PluginTrustBody 是 PluginTrust 的信任块。blockedFromDownload 为权威阻断信号。
type PluginTrustBody struct {
	ScanStatus          string   `json:"scanStatus"` // clean|suspicious|malicious|pending|not-run
	ModerationState     string   `json:"moderationState,omitempty"`
	BlockedFromDownload bool     `json:"blockedFromDownload"`
	Reasons             []string `json:"reasons"`
	Pending             bool     `json:"pending,omitempty"`
	Stale               bool     `json:"stale,omitempty"`
}

// PluginTrust 是 plugin 单查安装阻断响应。
type PluginTrust struct {
	Package PluginTrustPkg     `json:"package"`
	Release PluginTrustRelease `json:"release"`
	Trust   PluginTrustBody    `json:"trust"`
}

// ─── 安装遥测（§3.8）───

// TelemetrySkill 是遥测中某根下已装 skill。
type TelemetrySkill struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

// TelemetryPlugin 是遥测中某根下已装 plugin。
type TelemetryPlugin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// TelemetryRoot 是单个安装根的状态快照。
type TelemetryRoot struct {
	RootID  string            `json:"rootId"`
	Label   string            `json:"label"`
	Skills  []TelemetrySkill  `json:"skills"`
	Plugins []TelemetryPlugin `json:"plugins"`
}

// TelemetryReport 是安装遥测上报体（按 root 做状态快照对账，非自增）。
type TelemetryReport struct {
	Roots []TelemetryRoot `json:"roots"`
}

// verdictRequest 是批量裁决请求体。
type verdictRequest struct {
	Items []VerdictRequestItem `json:"items"`
}

func (c *httpClient) SecurityVerdicts(ctx context.Context, items []VerdictRequestItem) (*SecurityVerdictResult, error) {
	var out SecurityVerdictResult
	if err := c.post(ctx, "/skills/-/security-verdicts", verdictRequest{Items: items}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *httpClient) PackageSecurity(ctx context.Context, name, version string) (*PluginTrust, error) {
	path := "/packages/" + url.PathEscape(name) + "/releases/" + url.PathEscape(version) + "/security"
	var out PluginTrust
	if err := c.get(ctx, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *httpClient) ReportInstall(ctx context.Context, report TelemetryReport) error {
	return c.post(ctx, "/telemetry/install", report, nil)
}
