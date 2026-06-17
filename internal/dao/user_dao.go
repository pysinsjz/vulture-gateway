// Package dao 是数据访问层。
package dao

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pysinsjz/vulture-gateway/internal/model"
	"github.com/pysinsjz/vulture-gateway/internal/pkg/idgen"
)

// UserRepository 是 User 的数据访问契约。接口化以便上层逻辑可对内存假实现测试，
// 真实实现走 GORM/PostgreSQL（ADR-0001）。
type UserRepository interface {
	// ResolveOrCreateBySubject 按上游 OIDC subject 解析 User，不存在则创建。幂等。
	ResolveOrCreateBySubject(ctx context.Context, subject string) (*model.User, error)
}

type userDAO struct {
	db *gorm.DB
}

// NewUserDAO 构造 GORM 实现。
func NewUserDAO(db *gorm.DB) UserRepository {
	return &userDAO{db: db}
}

func (d *userDAO) ResolveOrCreateBySubject(ctx context.Context, subject string) (*model.User, error) {
	var user model.User

	// 先查。
	err := dbFrom(ctx, d.db).Where("subject = ?", subject).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("按 subject 查询 User 失败: %w", err)
	}

	// 不存在则创建；OnConflict 兜底并发创建竞态（subject 唯一）。
	newUser := model.User{UUID: idgen.New("usr"), Subject: subject}
	if err := dbFrom(ctx, d.db).
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "subject"}}, DoNothing: true}).
		Create(&newUser).Error; err != nil {
		return nil, fmt.Errorf("创建 User 失败: %w", err)
	}

	// 若发生冲突（DoNothing 未写入），newUser.ID 仍为 0，回查取到既有行。
	if newUser.ID == 0 {
		if err := dbFrom(ctx, d.db).Where("subject = ?", subject).First(&user).Error; err != nil {
			return nil, fmt.Errorf("冲突后回查 User 失败: %w", err)
		}
		return &user, nil
	}
	return &newUser, nil
}
