package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/pysinsjz/vulture-gateway/internal/handler"
	"github.com/pysinsjz/vulture-gateway/internal/middleware"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// whoamiResp 是 Whoami 的响应结构。
type whoamiResp struct {
	Sub      string `json:"sub"`
	DeviceID string `json:"device_id"`
	Email    string `json:"email"`
}

// newWhoamiEngine 装配一个注入了 sub/device_id 的 whoami 引擎（绕过真实 JWTAuth，仅验证 handler 行为）。
func newWhoamiEngine(repo *fakeIdentityRepo, sub, deviceID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	probe := handler.NewProbeHandler(repo)
	r.GET("/api/v1/whoami", func(c *gin.Context) {
		c.Set(middleware.CtxKeySub, sub)
		c.Set(middleware.CtxKeyDeviceID, deviceID)
		probe.Whoami(c)
	})
	return r
}

func doWhoami(t *testing.T, e *gin.Engine) whoamiResp {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("whoami 期望 200, 实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp whoamiResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 whoami 响应失败: %v", err)
	}
	return resp
}

// 绑定了 email Identity 的用户：whoami 返回其邮箱。
func TestWhoami_ReturnsEmail(t *testing.T) {
	repo := newFakeIdentityRepo()
	repo.byKey[model.IdentityTypeEmail+"|pan@example.com"] = &model.Identity{
		UserUUID:   "user-42",
		Type:       model.IdentityTypeEmail,
		Identifier: "pan@example.com",
	}

	resp := doWhoami(t, newWhoamiEngine(repo, "user-42", "dev-42"))

	if resp.Sub != "user-42" || resp.DeviceID != "dev-42" {
		t.Errorf("claims 透传错误: sub=%q device_id=%q", resp.Sub, resp.DeviceID)
	}
	if resp.Email != "pan@example.com" {
		t.Errorf("email 期望 pan@example.com, 实际 %q", resp.Email)
	}
}

// 未绑定 email 的用户：email 为空字符串，探针仍 200。
func TestWhoami_NoEmailReturnsEmpty(t *testing.T) {
	resp := doWhoami(t, newWhoamiEngine(newFakeIdentityRepo(), "user-7", "dev-7"))

	if resp.Email != "" {
		t.Errorf("无邮箱用户 email 应为空, 实际 %q", resp.Email)
	}
}
