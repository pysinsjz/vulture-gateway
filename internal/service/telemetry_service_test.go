package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/clawhub"
	"github.com/pysinsjz/vulture-gateway/internal/service"
)

// fakeTelemetry 是 clawhub.TelemetryClient 的内存 fake。
type fakeTelemetry struct {
	got clawhub.TelemetryReport
	err error
}

func (f *fakeTelemetry) ReportInstall(_ context.Context, report clawhub.TelemetryReport) error {
	f.got = report
	return f.err
}

// 遥测转发：对外报告映射为 ClawHub 形态，skills/plugins 逐项透传。
func TestReportInstall_Forwards(t *testing.T) {
	fake := &fakeTelemetry{}
	svc := service.NewTelemetryService(fake)

	report := service.TelemetryReport{Roots: []service.TelemetryRoot{
		{
			RootID: "root-1", Label: "ws",
			Skills:  []service.TelemetrySkill{{Slug: "gifgrep", Version: "1.0.0"}},
			Plugins: []service.TelemetryPlugin{{Name: "@v/x", Version: "0.4.1"}},
		},
	}}
	if err := svc.ReportInstall(context.Background(), report); err != nil {
		t.Fatalf("ReportInstall 失败: %v", err)
	}
	if len(fake.got.Roots) != 1 || fake.got.Roots[0].RootID != "root-1" {
		t.Fatalf("root 透传错误: %+v", fake.got.Roots)
	}
	r := fake.got.Roots[0]
	if len(r.Skills) != 1 || r.Skills[0].Slug != "gifgrep" {
		t.Errorf("skills 透传错误: %+v", r.Skills)
	}
	if len(r.Plugins) != 1 || r.Plugins[0].Name != "@v/x" {
		t.Errorf("plugins 透传错误: %+v", r.Plugins)
	}
}

// 上游错误原样上抛（由 handler best-effort 吞掉）。
func TestReportInstall_PropagatesError(t *testing.T) {
	wantErr := errors.New("upstream down")
	fake := &fakeTelemetry{err: wantErr}
	svc := service.NewTelemetryService(fake)

	if err := svc.ReportInstall(context.Background(), service.TelemetryReport{}); !errors.Is(err, wantErr) {
		t.Errorf("应上抛上游错误, 实际 %v", err)
	}
}
