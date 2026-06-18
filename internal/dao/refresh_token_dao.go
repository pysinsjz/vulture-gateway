package dao

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// RefreshTokenRepository 是 refresh token 的数据访问契约。
type RefreshTokenRepository interface {
	// Create 持久化一条 refresh token 记录。
	Create(ctx context.Context, rt *model.RefreshToken) error
	// FindByHash 按 token 哈希查找。found=false 表示不存在。
	FindByHash(ctx context.Context, tokenHash string) (rt *model.RefreshToken, found bool, err error)
	// MarkUsedIfUnused 原子地将未使用的 token 标记为已使用（轮换消费）。
	// flipped=true 表示本次成功翻转（竞态胜者）；false 表示已被他人翻转。
	MarkUsedIfUnused(ctx context.Context, tokenHash string) (flipped bool, err error)
	// RevokeFamily 作废整个轮换家族（判盗）。
	RevokeFamily(ctx context.Context, familyID string) error
	// RevokeByDevice 作废某 Device 的全部 refresh（登出/吊销设备）。
	RevokeByDevice(ctx context.Context, deviceUUID string) error
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

func (d *refreshTokenDAO) FindByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, bool, error) {
	var rt model.RefreshToken
	err := dbFrom(ctx, d.db).Where("token_hash = ?", tokenHash).First(&rt).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("查询 refresh token 失败: %w", err)
	}
	return &rt, true, nil
}

func (d *refreshTokenDAO) MarkUsedIfUnused(ctx context.Context, tokenHash string) (bool, error) {
	res := dbFrom(ctx, d.db).Model(&model.RefreshToken{}).
		Where("token_hash = ? AND used = ?", tokenHash, false).
		Update("used", true)
	if res.Error != nil {
		return false, fmt.Errorf("标记 refresh token 已用失败: %w", res.Error)
	}
	return res.RowsAffected == 1, nil
}

func (d *refreshTokenDAO) RevokeFamily(ctx context.Context, familyID string) error {
	if err := dbFrom(ctx, d.db).Model(&model.RefreshToken{}).
		Where("family_id = ?", familyID).
		Update("revoked", true).Error; err != nil {
		return fmt.Errorf("作废 refresh 家族失败: %w", err)
	}
	return nil
}

func (d *refreshTokenDAO) RevokeByDevice(ctx context.Context, deviceUUID string) error {
	if err := dbFrom(ctx, d.db).Model(&model.RefreshToken{}).
		Where("device_uuid = ?", deviceUUID).
		Update("revoked", true).Error; err != nil {
		return fmt.Errorf("按 Device 作废 refresh 失败: %w", err)
	}
	return nil
}
