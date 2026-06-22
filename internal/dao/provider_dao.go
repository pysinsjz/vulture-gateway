package dao

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// ProviderRepository 是 Provider（认证渠道配置）的数据访问契约。
type ProviderRepository interface {
	// FindByCategory 列出某类别（email/sms/oauth）启用的 provider。
	FindByCategory(ctx context.Context, category string) ([]model.Provider, error)
	// UpsertSeed 按 name 幂等 upsert 一条 provider（启动 config seed 用）。
	UpsertSeed(ctx context.Context, provider *model.Provider) error
}

type providerDAO struct {
	db *gorm.DB
}

// NewProviderDAO 构造 GORM 实现。
func NewProviderDAO(db *gorm.DB) ProviderRepository {
	return &providerDAO{db: db}
}

func (d *providerDAO) FindByCategory(ctx context.Context, category string) ([]model.Provider, error) {
	var providers []model.Provider
	err := dbFrom(ctx, d.db).Where("category = ? AND enabled = ?", category, true).Find(&providers).Error
	if err != nil {
		return nil, fmt.Errorf("按类别查询 provider 失败: %w", err)
	}
	return providers, nil
}

func (d *providerDAO) UpsertSeed(ctx context.Context, provider *model.Provider) error {
	// 按 name 冲突则更新配置列（seed 重启幂等）；不动 created_at。
	err := dbFrom(ctx, d.db).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"category", "type", "client_id", "client_secret", "host", "port", "enabled", "updated_at",
		}),
	}).Create(provider).Error
	if err != nil {
		return fmt.Errorf("upsert provider seed 失败: %w", err)
	}
	return nil
}
