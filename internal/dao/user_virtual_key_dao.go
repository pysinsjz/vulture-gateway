package dao

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// UserVirtualKeyRepository 是 User 专属 litellm virtual key 的数据访问契约（ADR-0014）。
// 接口化以便 VirtualKeyService 用内存假实现单测；真实实现走 GORM/PostgreSQL。
type UserVirtualKeyRepository interface {
	// GetByUserUUID 按用户解析其 virtual key。found=false 表示尚未签发。
	GetByUserUUID(ctx context.Context, userUUID string) (*model.UserVirtualKey, bool, error)
	// Create 首签插入。user_uuid 唯一冲突时 inserted=false（并发首签竞态，调用方应删孤儿 key 并回查）。
	Create(ctx context.Context, vk *model.UserVirtualKey) (inserted bool, err error)
	// Replace 原行覆盖为新 key（自愈轮换）：保 1:1 不破唯一约束。按 user_uuid 更新 key/token/alias/status=active。
	Replace(ctx context.Context, userUUID, litellmKey, keyAlias, tokenID string) error
	// DeleteByUserUUID 物理删除某用户的 key 行（删/封用户接缝，v1 未接线）。
	DeleteByUserUUID(ctx context.Context, userUUID string) error
}

type userVirtualKeyDAO struct {
	db *gorm.DB
}

// NewUserVirtualKeyDAO 构造 GORM 实现。
func NewUserVirtualKeyDAO(db *gorm.DB) UserVirtualKeyRepository {
	return &userVirtualKeyDAO{db: db}
}

func (d *userVirtualKeyDAO) GetByUserUUID(ctx context.Context, userUUID string) (*model.UserVirtualKey, bool, error) {
	var vk model.UserVirtualKey
	err := dbFrom(ctx, d.db).Where("user_uuid = ?", userUUID).First(&vk).Error
	if err == nil {
		return &vk, true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("按 user_uuid 查询 virtual key 失败: %w", err)
}

func (d *userVirtualKeyDAO) Create(ctx context.Context, vk *model.UserVirtualKey) (bool, error) {
	// OnConflict DoNothing 兜底并发首签竞态（user_uuid 唯一）。冲突时 RowsAffected==0。
	res := dbFrom(ctx, d.db).
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "user_uuid"}}, DoNothing: true}).
		Create(vk)
	if res.Error != nil {
		return false, fmt.Errorf("创建 virtual key 失败: %w", res.Error)
	}
	return res.RowsAffected > 0, nil
}

func (d *userVirtualKeyDAO) Replace(ctx context.Context, userUUID, litellmKey, keyAlias, tokenID string) error {
	err := dbFrom(ctx, d.db).Model(&model.UserVirtualKey{}).
		Where("user_uuid = ?", userUUID).
		Updates(map[string]interface{}{
			"litellm_key": litellmKey,
			"key_alias":   keyAlias,
			"token_id":    tokenID,
			"status":      model.VirtualKeyStatusActive,
		}).Error
	if err != nil {
		return fmt.Errorf("覆盖 virtual key 失败: %w", err)
	}
	return nil
}

func (d *userVirtualKeyDAO) DeleteByUserUUID(ctx context.Context, userUUID string) error {
	if err := dbFrom(ctx, d.db).Where("user_uuid = ?", userUUID).Delete(&model.UserVirtualKey{}).Error; err != nil {
		return fmt.Errorf("删除 virtual key 失败: %w", err)
	}
	return nil
}
