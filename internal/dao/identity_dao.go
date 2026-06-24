package dao

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/pysinsjz/vulture-gateway/internal/model"
)

// IdentityRepository 是 Identity（登录身份）的数据访问契约。
// 接口化以便上层 SigninMethod 逻辑对内存假实现测试，真实实现走 GORM/PostgreSQL。
type IdentityRepository interface {
	// FindByTypeIdentifier 按 (type, identifier) 查找登录身份。found=false 表示不存在。
	FindByTypeIdentifier(ctx context.Context, typ, identifier string) (identity *model.Identity, found bool, err error)
	// FindByUserUUIDAndType 按 (user_uuid, type) 查找登录身份，用于回查某 User 的邮箱/手机标识。
	// found=false 表示该 User 未绑定该类型身份。
	FindByUserUUIDAndType(ctx context.Context, userUUID, typ string) (identity *model.Identity, found bool, err error)
	// Create 持久化一条 Identity。须在事务内与 User 同步创建（登录即注册）。
	Create(ctx context.Context, identity *model.Identity) error
}

type identityDAO struct {
	db *gorm.DB
}

// NewIdentityDAO 构造 GORM 实现。
func NewIdentityDAO(db *gorm.DB) IdentityRepository {
	return &identityDAO{db: db}
}

func (d *identityDAO) FindByTypeIdentifier(ctx context.Context, typ, identifier string) (*model.Identity, bool, error) {
	var identity model.Identity
	err := dbFrom(ctx, d.db).Where("type = ? AND identifier = ?", typ, identifier).First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("按 type+identifier 查询 Identity 失败: %w", err)
	}
	return &identity, true, nil
}

func (d *identityDAO) FindByUserUUIDAndType(ctx context.Context, userUUID, typ string) (*model.Identity, bool, error) {
	var identity model.Identity
	err := dbFrom(ctx, d.db).Where("user_uuid = ? AND type = ?", userUUID, typ).First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("按 user_uuid+type 查询 Identity 失败: %w", err)
	}
	return &identity, true, nil
}

func (d *identityDAO) Create(ctx context.Context, identity *model.Identity) error {
	if err := dbFrom(ctx, d.db).Create(identity).Error; err != nil {
		return fmt.Errorf("创建 Identity 失败: %w", err)
	}
	return nil
}
