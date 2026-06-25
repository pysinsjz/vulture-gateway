package litellm_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pysinsjz/vulture-gateway/internal/litellm"
)

// 正路：GenerateKey 注入 Master Key、下发 alias/user_id/max_budget，解析 key + token_id；models 空时不下发该字段。
func TestGenerateKey_InjectsMasterKeyAndParses(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":"sk-user-abc","token_id":"tok-1","user_id":"usr-1"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	gen, err := c.GenerateKey(context.Background(), litellm.GenerateKeyParams{
		KeyAlias:  "user-usr-1",
		UserID:    "usr-1",
		MaxBudget: 9999999,
	})
	if err != nil {
		t.Fatalf("GenerateKey 失败: %v", err)
	}
	if gotPath != "/key/generate" {
		t.Errorf("路径 = %q, 期望 /key/generate", gotPath)
	}
	if gotAuth != "Bearer sk-master" {
		t.Errorf("应注入 Master Key, 实际 %q", gotAuth)
	}
	if gen.Key != "sk-user-abc" || gen.TokenID != "tok-1" {
		t.Errorf("解析错误: %+v", gen)
	}
	if gotBody["key_alias"] != "user-usr-1" || gotBody["user_id"] != "usr-1" {
		t.Errorf("签发参数错误: %+v", gotBody)
	}
	if gotBody["max_budget"].(float64) != 9999999 {
		t.Errorf("max_budget 应为保险丝值, 实际 %v", gotBody["max_budget"])
	}
	if _, ok := gotBody["models"]; ok {
		t.Errorf("models 空时不应下发该字段（避免部分版本视空数组为无权）: %+v", gotBody)
	}
}

// models 非空时下发该字段。
func TestGenerateKey_SendsModelsWhenSet(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"key":"sk-x"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	if _, err := c.GenerateKey(context.Background(), litellm.GenerateKeyParams{Models: []string{"gpt-4"}}); err != nil {
		t.Fatalf("GenerateKey 失败: %v", err)
	}
	models, ok := gotBody["models"].([]interface{})
	if !ok || len(models) != 1 || models[0] != "gpt-4" {
		t.Errorf("models 应下发 [gpt-4], 实际 %+v", gotBody["models"])
	}
}

// token_id 缺失时回退 token 字段。
func TestGenerateKey_FallsBackToTokenField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"key":"sk-x","token":"tok-fallback"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	gen, err := c.GenerateKey(context.Background(), litellm.GenerateKeyParams{})
	if err != nil {
		t.Fatalf("GenerateKey 失败: %v", err)
	}
	if gen.TokenID != "tok-fallback" {
		t.Errorf("token_id 应回退 token 字段, 实际 %q", gen.TokenID)
	}
}

// 上游非 2xx → 返回错误（非静默成功）。
func TestGenerateKey_UpstreamErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid master key"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "wrong", srv.Client())
	if _, err := c.GenerateKey(context.Background(), litellm.GenerateKeyParams{}); err == nil {
		t.Fatal("期望错误, 实际 nil")
	}
}

// 响应缺 key 字段 → 错误（防把空 key 落库）。
func TestGenerateKey_MissingKeyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_id":"tok-1"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	if _, err := c.GenerateKey(context.Background(), litellm.GenerateKeyParams{}); err == nil {
		t.Fatal("期望错误（无 key）, 实际 nil")
	}
}

// DeleteKey 注入 Master Key，按 keys 数组下发待删 key。
func TestDeleteKey_PostsKeysWithMaster(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"deleted_keys":["sk-x"]}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	if err := c.DeleteKey(context.Background(), "sk-x"); err != nil {
		t.Fatalf("DeleteKey 失败: %v", err)
	}
	if gotPath != "/key/delete" || gotAuth != "Bearer sk-master" {
		t.Errorf("path=%q auth=%q", gotPath, gotAuth)
	}
	keys, ok := gotBody["keys"].([]interface{})
	if !ok || len(keys) != 1 || keys[0] != "sk-x" {
		t.Errorf("keys 应为 [sk-x], 实际 %+v", gotBody["keys"])
	}
}

// DeleteKey 上游非 2xx → 错误。
func TestDeleteKey_UpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	if err := c.DeleteKey(context.Background(), "sk-x"); err == nil {
		t.Fatal("期望错误, 实际 nil")
	}
}
