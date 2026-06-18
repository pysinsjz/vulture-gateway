package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// 本文件汇集安全裁决相关的对外契约与翻译（#22）：
//   - skill 批量裁决（SkillService.SecurityVerdicts）→ ClawHub /skills/-/security-verdicts
//   - plugin 单查安装阻断（PluginService.PluginSecurity）→ ClawHub /packages/{name}/releases/{version}/security
// 二者均为网关透传：ClawHub 是裁决权威，网关只翻译形态、按 ADR-0011 映射错误。

// VerdictQuery 是批量裁决请求的单项（对外，§3.6）。
type VerdictQuery struct {
	Slug    string `json:"slug" binding:"required"`
	Version string `json:"version" binding:"required"`
}

// StaticScan 是确定性静态扫描结果（对外）。
type StaticScan struct {
	Status      string   `json:"status"`
	ReasonCodes []string `json:"reasonCodes,omitempty"`
}

// SecuritySignals 是各扫描信号明细（对外）。
type SecuritySignals struct {
	StaticScan *StaticScan `json:"staticScan,omitempty"`
}

// SecurityStatus 是安全状态详情（对外）。放行一律以 VerdictItem.Decision 为准。
type SecurityStatus struct {
	Status  string           `json:"status"`
	Passed  bool             `json:"passed"`
	Signals *SecuritySignals `json:"signals,omitempty"`
}

// VerdictError 是裁决项查询失败时的错误（对外）。
type VerdictError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// VerdictItem 是单个 skill 版本的裁决结果（对外）。
type VerdictItem struct {
	OK               bool            `json:"ok"`
	Decision         string          `json:"decision"`
	Reasons          []string        `json:"reasons"`
	RequestedSlug    string          `json:"requestedSlug"`
	Slug             string          `json:"slug,omitempty"`
	DisplayName      string          `json:"displayName,omitempty"`
	RequestedVersion string          `json:"requestedVersion"`
	Version          string          `json:"version,omitempty"`
	Security         *SecurityStatus `json:"security"`
	Error            *VerdictError   `json:"error,omitempty"`
}

// SecurityVerdictResponse 是批量裁决的对外响应（§3.6）。
type SecurityVerdictResponse struct {
	Schema string        `json:"schema"`
	Items  []VerdictItem `json:"items"`
}

// PluginTrustPkg / PluginTrustRelease / PluginTrustBody / PluginTrust 是 plugin 单查安装阻断的对外契约（§3.6）。
type PluginTrustPkg struct {
	Name string `json:"name"`
}

type PluginTrustRelease struct {
	Version        string `json:"version"`
	ArtifactSha256 string `json:"artifactSha256"`
}

type PluginTrustBody struct {
	ScanStatus          string   `json:"scanStatus"`
	ModerationState     string   `json:"moderationState,omitempty"`
	BlockedFromDownload bool     `json:"blockedFromDownload"`
	Reasons             []string `json:"reasons"`
	Pending             bool     `json:"pending,omitempty"`
	Stale               bool     `json:"stale,omitempty"`
}

type PluginTrust struct {
	Package PluginTrustPkg     `json:"package"`
	Release PluginTrustRelease `json:"release"`
	Trust   PluginTrustBody    `json:"trust"`
}

// SecurityVerdicts 批量查询 skill 安全裁决（1–100），转发 ClawHub 并翻译。
// 项数校验在 handler 层完成；ClawHub 错误原样上抛由 handler 按 ADR-0011 重映射。
func (s *SkillService) SecurityVerdicts(ctx context.Context, queries []VerdictQuery) (*SecurityVerdictResponse, error) {
	items := make([]clawhub.VerdictRequestItem, 0, len(queries))
	for _, q := range queries {
		items = append(items, clawhub.VerdictRequestItem{Slug: q.Slug, Version: q.Version})
	}

	res, err := s.hub.SecurityVerdicts(ctx, items)
	if err != nil {
		return nil, err
	}

	out := &SecurityVerdictResponse{Schema: res.Schema, Items: make([]VerdictItem, 0, len(res.Items))}
	for _, it := range res.Items {
		out.Items = append(out.Items, translateVerdictItem(it))
	}
	return out, nil
}

// PluginSecurity 单查 plugin 版本的安装阻断信号（PluginTrust），转发 ClawHub 并翻译。
func (s *PluginService) PluginSecurity(ctx context.Context, name, version string) (*PluginTrust, error) {
	t, err := s.hub.PackageSecurity(ctx, name, version)
	if err != nil {
		return nil, err
	}
	return &PluginTrust{
		Package: PluginTrustPkg{Name: t.Package.Name},
		Release: PluginTrustRelease{Version: t.Release.Version, ArtifactSha256: t.Release.ArtifactSha256},
		Trust: PluginTrustBody{
			ScanStatus:          t.Trust.ScanStatus,
			ModerationState:     t.Trust.ModerationState,
			BlockedFromDownload: t.Trust.BlockedFromDownload,
			Reasons:             t.Trust.Reasons,
			Pending:             t.Trust.Pending,
			Stale:               t.Trust.Stale,
		},
	}, nil
}

func translateVerdictItem(it clawhub.VerdictItem) VerdictItem {
	out := VerdictItem{
		OK:               it.OK,
		Decision:         it.Decision,
		Reasons:          it.Reasons,
		RequestedSlug:    it.RequestedSlug,
		Slug:             it.Slug,
		DisplayName:      it.DisplayName,
		RequestedVersion: it.RequestedVersion,
		Version:          it.Version,
		Security:         translateSecurityStatus(it.Security),
	}
	if it.Error != nil {
		out.Error = &VerdictError{Code: it.Error.Code, Message: it.Error.Message}
	}
	return out
}

func translateSecurityStatus(s *clawhub.SecurityStatus) *SecurityStatus {
	if s == nil {
		return nil
	}
	out := &SecurityStatus{Status: s.Status, Passed: s.Passed}
	if s.Signals != nil && s.Signals.StaticScan != nil {
		out.Signals = &SecuritySignals{StaticScan: &StaticScan{
			Status:      s.Signals.StaticScan.Status,
			ReasonCodes: s.Signals.StaticScan.ReasonCodes,
		}}
	}
	return out
}
