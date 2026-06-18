package model

// RefreshToken 是不透明 refresh token 的服务端记录。绑定 Device，归属一个轮换家族（FamilyID）；
// 每次使用轮换（#13），出示已被取代的 token 视为失窃、作废整个家族。寿命滑动续期（空闲 60 天过期）。
//
// 仅存 token 的哈希（TokenHash），不存明文：刷新时按出示 token 的哈希查找。
type RefreshToken struct {
	ID         int64  `json:"id" gorm:"column:id;type:bigserial;primaryKey;comment:自增ID"`
	TokenHash  string `json:"-" gorm:"column:token_hash;type:varchar(64);not null;uniqueIndex;comment:token 的 sha256 十六进制"`
	FamilyID   string `json:"family_id" gorm:"column:family_id;type:varchar(50);not null;index;comment:轮换家族ID"`
	DeviceUUID string `json:"device_uuid" gorm:"column:device_uuid;type:varchar(50);not null;index;comment:绑定 Device"`
	UserUUID   string `json:"user_uuid" gorm:"column:user_uuid;type:varchar(50);not null;index;comment:所属 User"`
	Used       bool   `json:"used" gorm:"column:used;not null;default:false;comment:是否已被轮换消费"`
	Revoked    bool   `json:"revoked" gorm:"column:revoked;not null;default:false;comment:家族是否已作废（判盗）"`
	CreatedAt  int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;comment:创建时间"`
	LastUsedAt int64  `json:"last_used_at" gorm:"column:last_used_at;comment:最近使用时间（滑动续期基准）"`
	ExpiresAt  int64  `json:"expires_at" gorm:"column:expires_at;not null;index;comment:过期时间（Unix 秒）"`
}

// TableName 表名。
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
