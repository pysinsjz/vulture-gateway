package model

// Identity 登录身份类型。一个 User 可绑定多条 Identity（email + 手机 + 未来社会化登录）。
const (
	IdentityTypeEmail = "email" // 邮箱标识
	IdentityTypePhone = "phone" // 手机标识
	IdentityTypeOAuth = "oauth" // 第三方登录（Phase 3，预留）
)

// Identity 是 User 的一条登录身份（ADR-0013：User + Identity 分离表，不用 Casdoor 宽表）。
// 一个 identifier（邮箱/手机/第三方 sub）对应一条 Identity，归属一个 User。
// Secret 为密码 bcrypt hash；验证码登录建号时留空，表示尚未设密码、只能验证码登录。
type Identity struct {
	ID         int64  `json:"id" gorm:"column:id;type:bigserial;primaryKey;comment:自增ID"`
	UUID       string `json:"uuid" gorm:"column:uuid;type:varchar(50);not null;uniqueIndex;comment:对外唯一标识"`
	UserUUID   string `json:"user_uuid" gorm:"column:user_uuid;type:varchar(50);not null;index;comment:归属 User 的 uuid"`
	Type       string `json:"type" gorm:"column:type;type:varchar(20);not null;uniqueIndex:uk_type_identifier,priority:1;comment:身份类型 email/phone/oauth"`
	Identifier string `json:"identifier" gorm:"column:identifier;type:varchar(255);not null;uniqueIndex:uk_type_identifier,priority:2;comment:标识值（邮箱/手机/第三方sub）"`
	Secret     string `json:"-" gorm:"column:secret;type:varchar(255);not null;default:'';comment:密码 bcrypt hash，空表示仅验证码登录"`
	Provider   string `json:"provider" gorm:"column:provider;type:varchar(50);not null;default:'';comment:来源 provider（第三方登录用，本地登录空）"`
	CreatedAt  int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;comment:创建时间"`
	UpdatedAt  int64  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime;comment:更新时间"`
}

// TableName 表名。
func (Identity) TableName() string {
	return "identities"
}
