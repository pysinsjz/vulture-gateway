package service

import (
	"context"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
)

// TelemetrySkill / TelemetryPlugin / TelemetryRoot / TelemetryReport 是安装遥测上报的对外契约（§3.8）。
// 按 root 做状态快照（非自增），ClawHub 侧对账维护 installsCurrent/installsAllTime。
type TelemetrySkill struct {
	Slug    string `json:"slug" binding:"required"`
	Version string `json:"version" binding:"required"`
}

type TelemetryPlugin struct {
	Name    string `json:"name" binding:"required"`
	Version string `json:"version" binding:"required"`
}

type TelemetryRoot struct {
	RootID  string            `json:"rootId" binding:"required"`
	Label   string            `json:"label"`
	Skills  []TelemetrySkill  `json:"skills" binding:"dive"`
	Plugins []TelemetryPlugin `json:"plugins" binding:"dive"`
}

type TelemetryReport struct {
	Roots []TelemetryRoot `json:"roots" binding:"required,dive"`
}

// TelemetryService 把安装遥测转发到内网 ClawHub（#22）。对账（快照幂等）由 ClawHub 侧负责。
type TelemetryService struct {
	hub clawhub.TelemetryClient
}

// NewTelemetryService 构造服务。
func NewTelemetryService(hub clawhub.TelemetryClient) *TelemetryService {
	return &TelemetryService{hub: hub}
}

// ReportInstall 转发遥测体到 ClawHub。调用方按 best-effort 处理返回错误（失败静默）。
func (s *TelemetryService) ReportInstall(ctx context.Context, report TelemetryReport) error {
	roots := make([]clawhub.TelemetryRoot, 0, len(report.Roots))
	for _, r := range report.Roots {
		root := clawhub.TelemetryRoot{RootID: r.RootID, Label: r.Label}
		for _, sk := range r.Skills {
			root.Skills = append(root.Skills, clawhub.TelemetrySkill{Slug: sk.Slug, Version: sk.Version})
		}
		for _, p := range r.Plugins {
			root.Plugins = append(root.Plugins, clawhub.TelemetryPlugin{Name: p.Name, Version: p.Version})
		}
		roots = append(roots, root)
	}
	return s.hub.ReportInstall(ctx, clawhub.TelemetryReport{Roots: roots})
}
