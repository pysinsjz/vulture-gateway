//go:build integration

// 这些测试需要真实 PostgreSQL，默认不随 `go test ./...` 运行。
// 运行方式：VG_TEST_POSTGRES_DSN="host=... user=... dbname=... sslmode=disable" go test -tags=integration ./internal/dao/
package dao

import (
	"context"
	"os"
	"testing"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/db"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

func setupDB(t *testing.T) UserRepository {
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
	// 清理测试数据。
	gdb.Where("subject LIKE ?", "itest-%").Delete(&model.User{})
	return NewUserDAO(gdb)
}

func TestUserDAO_ResolveOrCreateBySubject_Integration(t *testing.T) {
	repo := setupDB(t)
	ctx := context.Background()
	subject := "itest-subject-1"

	// 首次：创建。
	u1, err := repo.ResolveOrCreateBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("首次创建失败: %v", err)
	}
	if u1.ID == 0 || u1.UUID == "" || u1.Subject != subject {
		t.Fatalf("创建结果异常: %+v", u1)
	}

	// 再次：解析到同一行（幂等）。
	u2, err := repo.ResolveOrCreateBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if u2.ID != u1.ID || u2.UUID != u1.UUID {
		t.Errorf("应解析到同一 User: %+v vs %+v", u2, u1)
	}
}

func TestDeviceAndRefreshDAO_Create_Integration(t *testing.T) {
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
	ctx := context.Background()

	deviceDAO := NewDeviceDAO(gdb)
	refreshDAO := NewRefreshTokenDAO(gdb)

	device := &model.Device{UUID: "dev_itest", UserUUID: "usr_itest", Name: "iMac", OS: "macOS", AppVersion: "1.0.0", LastActiveAt: 1}
	gdb.Where("uuid = ?", device.UUID).Delete(&model.Device{})
	if err := deviceDAO.Create(ctx, device); err != nil {
		t.Fatalf("创建 Device 失败: %v", err)
	}
	if device.ID == 0 {
		t.Error("Device.ID 应回填")
	}

	rt := &model.RefreshToken{TokenHash: "itest-hash", FamilyID: "rtf_itest", DeviceUUID: device.UUID, UserUUID: "usr_itest", ExpiresAt: 1 << 40}
	gdb.Where("token_hash = ?", rt.TokenHash).Delete(&model.RefreshToken{})
	if err := refreshDAO.Create(ctx, rt); err != nil {
		t.Fatalf("创建 refresh token 失败: %v", err)
	}
	if rt.ID == 0 {
		t.Error("RefreshToken.ID 应回填")
	}
}
