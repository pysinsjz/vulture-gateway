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

// 正路：GenerateKey 注入 Master Key、下发 alias/user_id/max_budget/team_id；models 字段不再下发（ADR-0016）。
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
		TeamID:    "team-uuid-1",
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
	if gotBody["team_id"] != "team-uuid-1" {
		t.Errorf("应下发 team_id=team-uuid-1, 实际 %+v", gotBody["team_id"])
	}
	if gotBody["max_budget"].(float64) != 9999999 {
		t.Errorf("max_budget 应为保险丝值, 实际 %v", gotBody["max_budget"])
	}
	// ADR-0016：models 字段彻底不下发，由 team 的 models 列表决定。
	// 实测 workaround litellm bug #3275：省略 models 让 /v1/models 自动展开 team 模型清单（而非 ["all-team-models"] 占位）。
	if _, ok := gotBody["models"]; ok {
		t.Errorf("ADR-0016：models 字段不应下发（team 控制模型）, 实际 %+v", gotBody)
	}
}

// TeamID 空时不下发 team_id 字段（防御性：避免空字符串被 litellm 解释为无效 team）。
func TestGenerateKey_OmitsTeamIDWhenEmpty(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"key":"sk-x"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	if _, err := c.GenerateKey(context.Background(), litellm.GenerateKeyParams{}); err != nil {
		t.Fatalf("GenerateKey 失败: %v", err)
	}
	if _, ok := gotBody["team_id"]; ok {
		t.Errorf("team_id 空时不应下发该字段, 实际 %+v", gotBody)
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

// ListTeams 正路：注入 Master Key，调 GET /team/list，解析 team_id/team_alias 字段（ADR-0016）。
func TestListTeams_ParsesTeamIDAndAlias(t *testing.T) {
	var gotAuth, gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"team_id":"uuid-1","team_alias":"team-pro","spend":0},
			{"team_id":"uuid-2","team_alias":"team-free","spend":1.5}
		]`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	teams, err := c.ListTeams(context.Background())
	if err != nil {
		t.Fatalf("ListTeams 失败: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/team/list" {
		t.Errorf("应 GET /team/list, 实际 %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer sk-master" {
		t.Errorf("应注入 Master Key, 实际 %q", gotAuth)
	}
	if len(teams) != 2 {
		t.Fatalf("应解析 2 个 team, 实际 %d", len(teams))
	}
	if teams[0].ID != "uuid-1" || teams[0].Alias != "team-pro" {
		t.Errorf("teams[0] 解析错误: %+v", teams[0])
	}
	if teams[1].ID != "uuid-2" || teams[1].Alias != "team-free" {
		t.Errorf("teams[1] 解析错误: %+v", teams[1])
	}
}

// ListTeams 兼容字典外壳（部分 litellm 版本可能用 {"data":[...]}）。
func TestListTeams_ParsesDictWrapper(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"team_id":"uuid-1","team_alias":"team-pro"}]}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	teams, err := c.ListTeams(context.Background())
	if err != nil {
		t.Fatalf("ListTeams 失败: %v", err)
	}
	if len(teams) != 1 || teams[0].Alias != "team-pro" {
		t.Errorf("应解析 dict 包装下的列表, 实际 %+v", teams)
	}
}

// ListTeams 空列表：合法返回 []，不报错（让 service 层 fail-closed）。
func TestListTeams_EmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "sk-master", srv.Client())
	teams, err := c.ListTeams(context.Background())
	if err != nil {
		t.Fatalf("空列表不应报错, 实际: %v", err)
	}
	if len(teams) != 0 {
		t.Errorf("应返回空切片, 实际 %+v", teams)
	}
}

// ListTeams 上游非 2xx → 错误透传（不静默成空）。
func TestListTeams_UpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid master key"}`))
	}))
	defer srv.Close()

	c := litellm.NewAdminClient(srv.URL, "wrong", srv.Client())
	if _, err := c.ListTeams(context.Background()); err == nil {
		t.Fatal("期望错误, 实际 nil")
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
