// Package model 定义数据库表结构。
package model

// User 是网关唯一的身份单元（单层 User，无团队/组织层；见 CONTEXT.md）。
// Subject 是上游 Identity Provider 认证出的 OIDC subject，网关据此解析/创建 User。
type User struct {
	ID        int64  `json:"id" gorm:"column:id;type:bigserial;primaryKey;comment:自增ID"`
	UUID      string `json:"uuid" gorm:"column:uuid;type:varchar(50);not null;uniqueIndex;comment:对外唯一标识"`
	Subject   string `json:"subject" gorm:"column:subject;type:varchar(255);not null;uniqueIndex;comment:上游 OIDC subject"`
	CreatedAt int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;comment:创建时间"`
	UpdatedAt int64  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime;comment:更新时间"`
}

// TableName 表名。
func (User) TableName() string {
	return "users"
}
