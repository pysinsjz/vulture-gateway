package dao

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// DeviceRepository 是 Device 的数据访问契约。
type DeviceRepository interface {
	// Create 创建一台 Device。
	Create(ctx context.Context, device *model.Device) error
	// ListByUser 列出某 User 的全部 Device，按创建时间升序。
	ListByUser(ctx context.Context, userUUID string) ([]model.Device, error)
	// GetByUUID 按 device_id 查找。found=false 表示不存在。
	GetByUUID(ctx context.Context, uuid string) (device *model.Device, found bool, err error)
	// UpdateLastActive 更新最近活跃时间（token 刷新时）。
	UpdateLastActive(ctx context.Context, uuid string, ts int64) error
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

func (d *deviceDAO) ListByUser(ctx context.Context, userUUID string) ([]model.Device, error) {
	var devices []model.Device
	if err := dbFrom(ctx, d.db).Where("user_uuid = ?", userUUID).Order("created_at asc").Find(&devices).Error; err != nil {
		return nil, fmt.Errorf("列出 User 的 Device 失败: %w", err)
	}
	return devices, nil
}

func (d *deviceDAO) GetByUUID(ctx context.Context, uuid string) (*model.Device, bool, error) {
	var device model.Device
	err := dbFrom(ctx, d.db).Where("uuid = ?", uuid).First(&device).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("查询 Device 失败: %w", err)
	}
	return &device, true, nil
}

func (d *deviceDAO) UpdateLastActive(ctx context.Context, uuid string, ts int64) error {
	if err := dbFrom(ctx, d.db).Model(&model.Device{}).
		Where("uuid = ?", uuid).
		Update("last_active_at", ts).Error; err != nil {
		return fmt.Errorf("更新 Device 活跃时间失败: %w", err)
	}
	return nil
}
