package dao

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// DeviceRepository 是 Device 的数据访问契约。
type DeviceRepository interface {
	// Create 创建一台 Device。
	Create(ctx context.Context, device *model.Device) error
}

type deviceDAO struct {
	db *gorm.DB
}

// NewDeviceDAO 构造 GORM 实现。
func NewDeviceDAO(db *gorm.DB) DeviceRepository {
	return &deviceDAO{db: db}
}

func (d *deviceDAO) Create(ctx context.Context, device *model.Device) error {
	if err := dbFrom(ctx, d.db).Create(device).Error; err != nil {
		return fmt.Errorf("创建 Device 失败: %w", err)
	}
	return nil
}
