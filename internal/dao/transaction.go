package dao

import (
	"context"

	"gorm.io/gorm"
)

// Transactor 提供事务边界。多步写操作用 WithinTx 包裹，回调内经 context 透传的事务句柄执行，
// 保证原子性（沿用 web-go 的 context 携带事务模式）。
type Transactor interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type txKey struct{}

type gormTransactor struct {
	db *gorm.DB
}

// NewTransactor 构造基于 GORM 的事务器。
func NewTransactor(db *gorm.DB) Transactor {
	return &gormTransactor{db: db}
}

func (t *gormTransactor) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return t.db.Transaction(func(tx *gorm.DB) error {
		return fn(context.WithValue(ctx, txKey{}, tx))
	})
}

// dbFrom 返回应使用的 *gorm.DB：若 context 携带事务则用事务句柄，否则用基础连接。均绑定 ctx。
func dbFrom(ctx context.Context, base *gorm.DB) *gorm.DB {
	if tx, ok := ctx.Value(txKey{}).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}
	return base.WithContext(ctx)
}
