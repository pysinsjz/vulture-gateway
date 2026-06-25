// Package db 负责数据库连接与迁移（ADR-0001：PostgreSQL）。
package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// NewPostgres 构造 GORM 连接。DisableAutomaticPing 让 Open 不在装配期连库（连通性由调用方在
// 启动时显式 Ping 校验），从而装配过程不依赖活动数据库——便于测试与无 DB 启动检查。
func NewPostgres(cfg config.PostgresConfig) (*gorm.DB, error) {
	gdb, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               newGormLogger(),
	})
	if err != nil {
		return nil, fmt.Errorf("打开 PostgreSQL 连接失败: %w", err)
	}
	return gdb, nil
}

// newGormLogger 构造 GORM 日志器：
//   - IgnoreRecordNotFoundError：record-not-found 是正常控制流（如 GetOrCreateVirtualKey 首签前查无、
//     ResolveOrCreateBySubject 查无即建），DAO 已用 errors.Is 处理，不应被当作错误日志打印（误导排障）。
//   - Colorful=false：容器日志无终端，ANSI 红色转义反而像报错。
//   - SlowThreshold：仍保留慢查询告警（>200ms）。
func newGormLogger() logger.Interface {
	return logger.New(
		log.New(os.Stdout, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)
}

// Ping 校验数据库连通性。
func Ping(ctx context.Context, gdb *gorm.DB) error {
	sqlDB, err := gdb.DB()
	if err != nil {
		return fmt.Errorf("获取底层 sql.DB 失败: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("PostgreSQL Ping 失败: %w", err)
	}
	return nil
}

// AutoMigrate 迁移当前已知的表结构。
func AutoMigrate(gdb *gorm.DB) error {
	if err := gdb.AutoMigrate(&model.User{}, &model.Identity{}, &model.Provider{}, &model.Device{}, &model.RefreshToken{}, &model.UserVirtualKey{}); err != nil {
		return fmt.Errorf("AutoMigrate 失败: %w", err)
	}
	return nil
}
