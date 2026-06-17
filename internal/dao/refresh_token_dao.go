package dao

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// RefreshTokenRepository 是 refresh token 的数据访问契约。
// #12 仅需 Create（首次签发）；轮换/复用判盗（#13）后续扩展。
type RefreshTokenRepository interface {
	// Create 持久化一条 refresh token 记录。
	Create(ctx context.Context, rt *model.RefreshToken) error
}

type refreshTokenDAO struct {
	db *gorm.DB
}

// NewRefreshTokenDAO 构造 GORM 实现。
func NewRefreshTokenDAO(db *gorm.DB) RefreshTokenRepository {
	return &refreshTokenDAO{db: db}
}

func (d *refreshTokenDAO) Create(ctx context.Context, rt *model.RefreshToken) error {
	if err := dbFrom(ctx, d.db).Create(rt).Error; err != nil {
		return fmt.Errorf("创建 refresh token 失败: %w", err)
	}
	return nil
}
