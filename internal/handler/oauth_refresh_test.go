package handler_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

type tokResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	DeviceID     string `json:"device_id"`
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func parseToken(t *testing.T, rec *httptest.ResponseRecorder) tokResp {
	t.Helper()
	var r tokResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("解析 token 响应失败: %v (body=%s)", err, rec.Body.String())
	}
	return r
}

// login 走完整 #12 首次登录，返回 (access, refresh, deviceID)。
func (f *oauthFixture) login(t *testing.T) (access, refresh, deviceID string) {
	t.Helper()
	redirectURI := "http://127.0.0.1:5173/callback"
	gw := f.obtainGWCode(t, challengeFor(pkceVerifier), redirectURI)
	rec := f.postJSON(t, "/oauth/token", tokenBody(gw, pkceVerifier, redirectURI))
	if rec.Code != http.StatusOK {
		t.Fatalf("login 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	r := parseToken(t, rec)
	return r.AccessToken, r.RefreshToken, r.DeviceID
}

func (f *oauthFixture) refresh(t *testing.T, rt string) *httptest.ResponseRecorder {
	t.Helper()
	return f.postJSON(t, "/oauth/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     "vulture-desktop",
	})
}

func (f *oauthFixture) whoamiCode(t *testing.T, access string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec.Code
}

// 正常轮换：旧 RT 换得新 access + 新 RT（≠旧），新 access 可用。
func TestRefresh_NormalRotation(t *testing.T) {
	f := newOAuthFixture(t)
	_, rt1, dev := f.login(t)

	rec := f.refresh(t, rt1)
	if rec.Code != http.StatusOK {
		t.Fatalf("刷新期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	p := parseToken(t, rec)
	if p.RefreshToken == "" || p.RefreshToken == rt1 {
		t.Errorf("RT 应轮换为新值, 实际 %q (旧 %q)", p.RefreshToken, rt1)
	}
	if p.AccessToken == "" || p.DeviceID != dev {
		t.Errorf("响应字段异常: %+v", p)
	}
	if f.whoamiCode(t, p.AccessToken) != http.StatusOK {
		t.Error("轮换后的新 access 应能访问受保护端点")
	}
}

// 60s 宽限窗内重放旧 RT → 得到与上次完全相同的一对令牌，且家族未作废。
func TestRefresh_GraceWindowReplay(t *testing.T) {
	f := newOAuthFixture(t)
	_, rt1, _ := f.login(t)

	first := parseToken(t, f.refresh(t, rt1)) // RT1 → RT2
	replayRec := f.refresh(t, rt1)            // 窗内重放旧 RT1
	if replayRec.Code != http.StatusOK {
		t.Fatalf("宽限窗重放期望 200, 实际 %d", replayRec.Code)
	}
	replay := parseToken(t, replayRec)
	if replay.AccessToken != first.AccessToken || replay.RefreshToken != first.RefreshToken {
		t.Errorf("宽限窗应重放同一对令牌\nfirst=%+v\nreplay=%+v", first, replay)
	}

	// 家族未作废：用轮换后的 RT2 仍能正常刷新。
	if rec := f.refresh(t, first.RefreshToken); rec.Code != http.StatusOK {
		t.Errorf("家族应存活, RT2 刷新期望 200, 实际 %d", rec.Code)
	}
}

// 窗外出示已被取代的旧 RT → 判盗：作废整个家族 + bump token_version，返回 401。
func TestRefresh_TheftOutsideWindow(t *testing.T) {
	f := newOAuthFixture(t)
	access0, rt1, _ := f.login(t)

	first := parseToken(t, f.refresh(t, rt1)) // RT1 → RT2，replay 缓存 TTL 60s

	// 宽限窗过去。
	f.mr.FastForward(61 * time.Second)

	rec := f.refresh(t, rt1) // 窗外重放旧 RT1 → 判盗
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("窗外判盗期望 401, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	assertOAuthError(t, rec, "invalid_grant")

	// 整个家族作废：RT2 也失效。
	if rec := f.refresh(t, first.RefreshToken); rec.Code != http.StatusUnauthorized {
		t.Errorf("判盗后家族应作废, RT2 刷新期望 401, 实际 %d", rec.Code)
	}
	// bump token_version → 首登的 access 立即失效。
	if f.whoamiCode(t, access0) != http.StatusUnauthorized {
		t.Error("判盗应 bump token_version，首登 access 应立即 401")
	}
}

// 已过期（空闲超 60 天）的 RT → 401 invalid_grant。
func TestRefresh_Expired(t *testing.T) {
	f := newOAuthFixture(t)
	plain := "rt_expired_sample"
	f.refreshes.inject(&model.RefreshToken{
		TokenHash:  hashHex(plain),
		FamilyID:   "fam_x",
		DeviceUUID: "dev_x",
		UserUUID:   "usr_x",
		ExpiresAt:  time.Now().Add(-time.Hour).Unix(),
	})

	rec := f.refresh(t, plain)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("过期 RT 期望 401, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// 并发出示同一 RT：结果一致（一个轮换、其余重放同一对），家族不被误判作废。
func TestRefresh_Concurrency(t *testing.T) {
	f := newOAuthFixture(t)
	_, rt1, _ := f.login(t)

	const n = 6
	recs := make([]*httptest.ResponseRecorder, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recs[i] = f.refresh(t, rt1)
		}(i)
	}
	wg.Wait()

	var wantAccess, wantRefresh string
	for i, rec := range recs {
		if rec.Code != http.StatusOK {
			t.Fatalf("并发刷新[%d] 期望 200, 实际 %d: %s", i, rec.Code, rec.Body.String())
		}
		p := parseToken(t, rec)
		if i == 0 {
			wantAccess, wantRefresh = p.AccessToken, p.RefreshToken
			continue
		}
		if p.AccessToken != wantAccess || p.RefreshToken != wantRefresh {
			t.Errorf("并发结果应一致, [%d] 与首个不同", i)
		}
	}

	// 家族存活：轮换后的 RT 仍可刷新。
	if rec := f.refresh(t, wantRefresh); rec.Code != http.StatusOK {
		t.Errorf("并发后家族应存活, 实际 %d", rec.Code)
	}
}

// 刷新时 Device 已被吊销（token_version 记录消失）→ 401 invalid_grant。
func TestRefresh_DeviceRevoked(t *testing.T) {
	f := newOAuthFixture(t)
	_, rt1, dev := f.login(t)

	// 模拟 Device 被吊销：清掉其 token_version 记录。
	if err := f.rdb.Del(t.Context(), "device:"+dev+":token_version").Err(); err != nil {
		t.Fatalf("删除 token_version 失败: %v", err)
	}

	rec := f.refresh(t, rt1)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Device 吊销后刷新期望 401, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// 轮换时遇并发竞态败者（MarkUsedIfUnused 返回 false）→ 退回宽限窗重放同一对。
func TestRefresh_ConcurrentRotationFallback(t *testing.T) {
	f := newOAuthFixture(t)
	_, rt1, _ := f.login(t)

	// 预置该 RT 的重放缓存（模拟竞态胜者已写入），并让本次轮换“抢锁失败”。
	pair := `{"access_token":"A_replayed","refresh_token":"R_replayed"}`
	if err := f.rdb.Set(t.Context(), "oauth:refresh:replay:"+hashHex(rt1), pair, time.Minute).Err(); err != nil {
		t.Fatalf("预置重放缓存失败: %v", err)
	}
	f.refreshes.failMarkUsed = true

	rec := f.refresh(t, rt1)
	if rec.Code != http.StatusOK {
		t.Fatalf("竞态败者应重放, 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	p := parseToken(t, rec)
	if p.AccessToken != "A_replayed" || p.RefreshToken != "R_replayed" {
		t.Errorf("应返回缓存的令牌对, 实际 %+v", p)
	}
}

// 未知 RT → 401 invalid_grant。
func TestRefresh_UnknownToken(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.refresh(t, "rt_unknown")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未知 RT 期望 401, 实际 %d", rec.Code)
	}
	assertOAuthError(t, rec, "invalid_grant")
}

// 缺 refresh_token → 400 invalid_request；client_id 错误 → 400 invalid_client。
func TestRefresh_BadRequest(t *testing.T) {
	f := newOAuthFixture(t)

	missing := f.postJSON(t, "/oauth/token", map[string]any{"grant_type": "refresh_token", "client_id": "vulture-desktop"})
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("缺 refresh_token 期望 400, 实际 %d", missing.Code)
	}
	assertOAuthError(t, missing, "invalid_request")

	wrongClient := f.postJSON(t, "/oauth/token", map[string]any{"grant_type": "refresh_token", "refresh_token": "rt_x", "client_id": "other"})
	if wrongClient.Code != http.StatusBadRequest {
		t.Fatalf("client_id 错误期望 400, 实际 %d", wrongClient.Code)
	}
	assertOAuthError(t, wrongClient, "invalid_client")
}
