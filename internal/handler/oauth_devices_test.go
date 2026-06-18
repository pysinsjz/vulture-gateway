package handler_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type deviceView struct {
	DeviceID     string `json:"device_id"`
	Name         string `json:"name"`
	OS           string `json:"os"`
	AppVersion   string `json:"app_version"`
	CreatedAt    int64  `json:"created_at"`
	LastActiveAt int64  `json:"last_active_at"`
	Current      bool   `json:"current"`
}

func (f *oauthFixture) authReq(method, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec
}

func (f *oauthFixture) logout(bearer string, body any) *httptest.ResponseRecorder {
	var r io.Reader = http.NoBody
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", r)
	if body != nil {
		b, _ := json.Marshal(body)
		req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec
}

// logout Bearer 路：bump 当前 Device token_version 并 204；原 access 立即失效，family 作废。
func TestLogout_BearerPath(t *testing.T) {
	f := newOAuthFixture(t)
	access0, rt1, _ := f.login(t)

	rec := f.logout(access0, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout 期望 204, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if f.whoamiCode(t, access0) != http.StatusUnauthorized {
		t.Error("logout 后原 access 应立即 401")
	}
	if rr := f.refresh(t, rt1); rr.Code != http.StatusUnauthorized {
		t.Errorf("logout 后 refresh 应 401（家族作废）, 实际 %d", rr.Code)
	}
}

// logout 兜底路：access 已失效，仅凭 body refresh_token 吊销对应家族并 204。
func TestLogout_RefreshFallback(t *testing.T) {
	f := newOAuthFixture(t)
	access0, rt1, _ := f.login(t)

	rec := f.logout("", map[string]any{"refresh_token": rt1})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("兜底 logout 期望 204, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if f.whoamiCode(t, access0) != http.StatusUnauthorized {
		t.Error("兜底 logout 后原 access 应 401")
	}
	if rr := f.refresh(t, rt1); rr.Code != http.StatusUnauthorized {
		t.Errorf("兜底 logout 后 refresh 应 401, 实际 %d", rr.Code)
	}
}

// logout 既无 Bearer 又无 refresh_token → 401 ApiError。
func TestLogout_NoCredential(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.logout("", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无凭据 logout 期望 401, 实际 %d", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" {
		t.Errorf("应返回 ApiError, body=%s", rec.Body.String())
	}
}

// logout 兜底路遇未知 refresh_token → 仍 204（幂等，不泄露 RT 是否存在）。
func TestLogout_UnknownRefreshToken(t *testing.T) {
	f := newOAuthFixture(t)
	rec := f.logout("", map[string]any{"refresh_token": "rt_unknown"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("未知 RT 兜底 logout 期望 204（幂等）, 实际 %d", rec.Code)
	}
}

// GET /devices 返回结构正确，正确标记 current。
func TestDevices_List(t *testing.T) {
	f := newOAuthFixture(t)
	accessA, _, devA := f.login(t)
	_, _, devB := f.login(t)

	rec := f.authReq(http.MethodGet, "/api/v1/devices", accessA)
	if rec.Code != http.StatusOK {
		t.Fatalf("devices 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var list []deviceView
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("解析设备列表失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("应有 2 台设备, 实际 %d", len(list))
	}
	byID := map[string]deviceView{}
	for _, d := range list {
		byID[d.DeviceID] = d
	}
	if !byID[devA].Current {
		t.Error("devA 应标记 current")
	}
	if byID[devB].Current {
		t.Error("devB 不应标记 current")
	}
	if byID[devA].Name != "Pan's Mac" || byID[devA].OS != "macOS 15.5" || byID[devA].AppVersion != "1.2.0" {
		t.Errorf("设备字段缺失: %+v", byID[devA])
	}
}

// DELETE /devices/{id} 204 后该设备在途 access 立即 401，不影响其它设备。
func TestDevices_DeleteInstantRevoke(t *testing.T) {
	f := newOAuthFixture(t)
	accessA, _, _ := f.login(t)
	accessB, _, devB := f.login(t)

	rec := f.authReq(http.MethodDelete, "/api/v1/devices/"+devB, accessA)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete 期望 204, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	if f.whoamiCode(t, accessB) != http.StatusUnauthorized {
		t.Error("被吊销设备的 access 应立即 401")
	}
	if f.whoamiCode(t, accessA) != http.StatusOK {
		t.Error("当前设备的 access 应仍可用")
	}
}

// DELETE 非本人设备 → 404。
func TestDevices_DeleteNotOwned(t *testing.T) {
	f := newOAuthFixture(t)
	accessA, _, _ := f.login(t)

	rec := f.authReq(http.MethodDelete, "/api/v1/devices/dev_not_mine", accessA)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("吊销不存在/非本人设备期望 404, 实际 %d", rec.Code)
	}
}

// last_active_at 随刷新更新，并在设备列表反映。
func TestLastActive_UpdatedOnRefresh(t *testing.T) {
	f := newOAuthFixture(t)
	accessA, rt1, _ := f.login(t)

	if f.devices.lastActiveUpdates != 0 {
		t.Fatalf("登录不应触发 last_active 更新, 实际 %d", f.devices.lastActiveUpdates)
	}
	if rr := f.refresh(t, rt1); rr.Code != http.StatusOK {
		t.Fatalf("刷新期望 200, 实际 %d", rr.Code)
	}
	if f.devices.lastActiveUpdates != 1 {
		t.Errorf("刷新应更新 last_active 一次, 实际 %d", f.devices.lastActiveUpdates)
	}

	rec := f.authReq(http.MethodGet, "/api/v1/devices", accessA)
	var list []deviceView
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].LastActiveAt == 0 {
		t.Errorf("设备列表应反映 last_active_at, 实际 %+v", list)
	}
}
