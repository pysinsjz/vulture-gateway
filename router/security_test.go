package router_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// skill 批量裁决：正负路 + pending 与 malicious 在 body 上可区分（均 decision=fail 保守不放行）。
func TestSecurityVerdicts_BatchAndPendingDistinct(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/skills/-/security-verdicts": ok(`{"schema":"clawhub.skill.security-verdicts.v1","items":[
			{"ok":true,"decision":"pass","reasons":[],"requestedSlug":"good","requestedVersion":"1.0.0","security":{"status":"clean","passed":true}},
			{"ok":true,"decision":"fail","reasons":["scan:malicious"],"requestedSlug":"evil","requestedVersion":"1.0.0","security":{"status":"malicious","passed":false}},
			{"ok":true,"decision":"fail","reasons":["scan:pending"],"requestedSlug":"new","requestedVersion":"1.0.0","security":{"status":"pending","passed":false}}
		]}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	body := map[string]any{"items": []map[string]string{
		{"slug": "good", "version": "1.0.0"},
		{"slug": "evil", "version": "1.0.0"},
		{"slug": "new", "version": "1.0.0"},
	}}
	rec := do(t, e, http.MethodPost, "/api/v1/skills/-/security-verdicts", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Schema string `json:"schema"`
		Items  []struct {
			Decision string `json:"decision"`
			Security *struct {
				Status string `json:"status"`
			} `json:"security"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v (%s)", err, rec.Body.String())
	}
	if resp.Schema != "clawhub.skill.security-verdicts.v1" || len(resp.Items) != 3 {
		t.Fatalf("响应形态错误: %+v", resp)
	}
	if resp.Items[0].Decision != "pass" {
		t.Errorf("第1项应 pass, 实际 %q", resp.Items[0].Decision)
	}
	// pending 与 malicious 都 fail（保守不放行），但 security.status 在 body 上区分。
	if resp.Items[1].Decision != "fail" || resp.Items[1].Security.Status != "malicious" {
		t.Errorf("malicious 项错误: %+v", resp.Items[1])
	}
	if resp.Items[2].Decision != "fail" || resp.Items[2].Security.Status != "pending" {
		t.Errorf("pending 项错误: %+v", resp.Items[2])
	}
}

// 批量裁决项数校验：0 项 / >100 项 → 400，网关侧即被拒（不触达 ClawHub）。
func TestSecurityVerdicts_ValidatesBatchSize(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	// 0 项。
	rec := do(t, e, http.MethodPost, "/api/v1/skills/-/security-verdicts", token, map[string]any{"items": []any{}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("0 项期望 400, 实际 %d", rec.Code)
	}
	assertApiError(t, rec)

	// 101 项。
	big := make([]map[string]string, 101)
	for i := range big {
		big[i] = map[string]string{"slug": "s", "version": "1.0.0"}
	}
	rec = do(t, e, http.MethodPost, "/api/v1/skills/-/security-verdicts", token, map[string]any{"items": big})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("101 项期望 400, 实际 %d", rec.Code)
	}
}

// plugin 单查：blockedFromDownload 权威信号透传；pending 与 malicious body 区分。
func TestPluginSecurity_TrustSignalPassthrough(t *testing.T) {
	stub := newCatalogStub(t, map[string]func() (int, string){
		"/packages/@v/x/releases/1.0.0/security": ok(`{"package":{"name":"@v/x"},"release":{"version":"1.0.0","artifactSha256":"abc"},"trust":{"scanStatus":"malicious","moderationState":"quarantined","blockedFromDownload":true,"reasons":["scan:malicious","manual:quarantined"]}}`),
		"/packages/@v/y/releases/1.0.0/security": ok(`{"package":{"name":"@v/y"},"release":{"version":"1.0.0","artifactSha256":"def"},"trust":{"scanStatus":"pending","blockedFromDownload":true,"reasons":["scan:pending"],"pending":true}}`),
	})
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	// malicious：blockedFromDownload=true + quarantined。
	rec := do(t, e, http.MethodGet, "/api/v1/plugins/@v%2Fx/versions/1.0.0/security", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var trust struct {
		Trust struct {
			ScanStatus          string `json:"scanStatus"`
			BlockedFromDownload bool   `json:"blockedFromDownload"`
			Pending             bool   `json:"pending"`
		} `json:"trust"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &trust); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !trust.Trust.BlockedFromDownload || trust.Trust.ScanStatus != "malicious" || trust.Trust.Pending {
		t.Errorf("malicious trust 错误: %+v", trust.Trust)
	}

	// pending：blockedFromDownload=true 但 pending=true（与 malicious 区分）。
	rec = do(t, e, http.MethodGet, "/api/v1/plugins/@v%2Fy/versions/1.0.0/security", token, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &trust); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !trust.Trust.BlockedFromDownload || trust.Trust.ScanStatus != "pending" || !trust.Trust.Pending {
		t.Errorf("pending trust 错误: %+v", trust.Trust)
	}
}

// telemetryStub 是有状态遥测桩：按 root 状态快照对账（非自增），暴露 installsCurrent 供断言。
type telemetryStub struct {
	srv       *httptest.Server
	mu        sync.Mutex
	rootSkill map[string]map[string]bool // rootId → set(slug)
}

func newTelemetryStub(t *testing.T, status int) *telemetryStub {
	t.Helper()
	s := &telemetryStub{rootSkill: map[string]map[string]bool{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
			return
		}
		var report struct {
			Roots []struct {
				RootID string `json:"rootId"`
				Skills []struct {
					Slug string `json:"slug"`
				} `json:"skills"`
			} `json:"roots"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &report)
		s.mu.Lock()
		// 状态快照对账：该 root 的已装集合被整体替换（非自增）。
		for _, root := range report.Roots {
			set := map[string]bool{}
			for _, sk := range root.Skills {
				set[sk.Slug] = true
			}
			s.rootSkill[root.RootID] = set
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// installsCurrent 统计当前持有某 slug 的 root 数（快照对账结果）。
func (s *telemetryStub) installsCurrent(slug string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, set := range s.rootSkill {
		if set[slug] {
			n++
		}
	}
	return n
}

// 遥测转发 + 幂等对账：同一报告上报两次，installsCurrent 收敛为 1（非自增）。
func TestTelemetry_ForwardsAndIdempotent(t *testing.T) {
	stub := newTelemetryStub(t, http.StatusOK)
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	report := map[string]any{"roots": []map[string]any{
		{"rootId": "root-1", "label": "ws", "skills": []map[string]string{{"slug": "gifgrep", "version": "1.0.0"}}, "plugins": []any{}},
	}}

	for i := 0; i < 2; i++ {
		rec := do(t, e, http.MethodPost, "/api/v1/telemetry/install", token, report)
		if rec.Code != http.StatusOK {
			t.Fatalf("第%d次期望 200, 实际 %d: %s", i+1, rec.Code, rec.Body.String())
		}
		var resp struct {
			OK bool `json:"ok"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if !resp.OK {
			t.Errorf("第%d次期望 {ok:true}, 实际 %s", i+1, rec.Body.String())
		}
	}
	if got := stub.installsCurrent("gifgrep"); got != 1 {
		t.Errorf("幂等对账失败：installsCurrent=%d, 期望 1（快照非自增）", got)
	}
}

// 遥测 best-effort：上游 ClawHub 失败也静默成功（{ok:true}），不让客户端重试风暴。
func TestTelemetry_BestEffortSwallowsUpstreamError(t *testing.T) {
	stub := newTelemetryStub(t, http.StatusInternalServerError)
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	report := map[string]any{"roots": []map[string]any{
		{"rootId": "root-1", "label": "ws", "skills": []map[string]string{{"slug": "x", "version": "1.0.0"}}, "plugins": []any{}},
	}}
	rec := do(t, e, http.MethodPost, "/api/v1/telemetry/install", token, report)
	if rec.Code != http.StatusOK {
		t.Fatalf("best-effort 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
}

// 遥测体格式错误 → 400。
func TestTelemetry_RejectsMalformed(t *testing.T) {
	stub := newTelemetryStub(t, http.StatusOK)
	e := newTestEngine(t, withClawHub(stub.srv.URL))
	token := issueViaScaffold(t, e, "u", "d")

	// 缺 roots。
	rec := do(t, e, http.MethodPost, "/api/v1/telemetry/install", token, map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 roots 期望 400, 实际 %d", rec.Code)
	}
	assertApiError(t, rec)
}
