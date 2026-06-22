//go:build integration

// 需要真实 PostgreSQL，默认不随 `go test ./...` 运行。
// 运行方式：VG_TEST_POSTGRES_DSN="host=... user=... dbname=... sslmode=disable" go test -tags=integration ./internal/dao/
package dao

import (
	"context"
	"os"
	"testing"

	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/db"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

func setupAuthDB(t *testing.T) (*gorm.DB, context.Context) {
	t.Helper()
	dsn := os.Getenv("VG_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("未设置 VG_TEST_POSTGRES_DSN，跳过 DAO 集成测试")
	}
	gdb, err := db.NewPostgres(config.PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatalf("连接 Postgres 失败: %v", err)
	}
	if err := db.AutoMigrate(gdb); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	// 清理本测试族数据。
	gdb.Where("identifier LIKE ?", "itest-%").Delete(&model.Identity{})
	gdb.Where("name LIKE ?", "itest-%").Delete(&model.Provider{})
	return gdb, context.Background()
}

func TestIdentityDAO_CreateAndFind_Integration(t *testing.T) {
	gdb, ctx := setupAuthDB(t)
	repo := NewIdentityDAO(gdb)

	// 未命中。
	if _, found, err := repo.FindByTypeIdentifier(ctx, model.IdentityTypeEmail, "itest-none@x.com"); err != nil || found {
		t.Fatalf("未存在身份应 found=false, found=%v err=%v", found, err)
	}

	id := &model.Identity{UUID: "idn_itest1", UserUUID: "usr_itest1", Type: model.IdentityTypeEmail, Identifier: "itest-a@x.com", Secret: "hash"}
	if err := repo.Create(ctx, id); err != nil {
		t.Fatalf("创建 Identity 失败: %v", err)
	}
	if id.ID == 0 {
		t.Error("Identity.ID 应回填")
	}

	got, found, err := repo.FindByTypeIdentifier(ctx, model.IdentityTypeEmail, "itest-a@x.com")
	if err != nil || !found {
		t.Fatalf("应命中, found=%v err=%v", found, err)
	}
	if got.UserUUID != "usr_itest1" || got.Secret != "hash" {
		t.Errorf("查询结果不符: %+v", got)
	}
}

func TestIdentityDAO_UniqueTypeIdentifier_Integration(t *testing.T) {
	gdb, ctx := setupAuthDB(t)
	repo := NewIdentityDAO(gdb)

	first := &model.Identity{UUID: "idn_itest2", UserUUID: "usr_itest2", Type: model.IdentityTypePhone, Identifier: "itest-13800000000"}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("首次创建失败: %v", err)
	}
	dup := &model.Identity{UUID: "idn_itest3", UserUUID: "usr_itest3", Type: model.IdentityTypePhone, Identifier: "itest-13800000000"}
	if err := repo.Create(ctx, dup); err == nil {
		t.Error("(type,identifier) 重复应违反唯一约束报错")
	}
}

func TestProviderDAO_UpsertSeedIdempotent_Integration(t *testing.T) {
	gdb, ctx := setupAuthDB(t)
	repo := NewProviderDAO(gdb)

	p := &model.Provider{UUID: "prv_itest1", Name: "itest-smtp", Category: model.ProviderCategoryEmail, Type: "smtp", Host: "smtp.x.com", Port: 587, Enabled: true}
	if err := repo.UpsertSeed(ctx, p); err != nil {
		t.Fatalf("首次 seed 失败: %v", err)
	}
	// 再次 upsert 更新端口，应幂等不报错。
	p2 := &model.Provider{UUID: "prv_itest1", Name: "itest-smtp", Category: model.ProviderCategoryEmail, Type: "smtp", Host: "smtp.x.com", Port: 465, Enabled: true}
	if err := repo.UpsertSeed(ctx, p2); err != nil {
		t.Fatalf("二次 seed 失败: %v", err)
	}

	list, err := repo.FindByCategory(ctx, model.ProviderCategoryEmail)
	if err != nil {
		t.Fatalf("按类别查询失败: %v", err)
	}
	var found *model.Provider
	for i := range list {
		if list[i].Name == "itest-smtp" {
			found = &list[i]
		}
	}
	if found == nil {
		t.Fatal("应查到 seed 的 email provider")
	}
	if found.Port != 465 {
		t.Errorf("upsert 应更新端口为 465, 实际 %d", found.Port)
	}
}
