package model

// 虚拟 key 状态（ADR-0014）。
const (
	VirtualKeyStatusActive  = "active"  // 当前可用
	VirtualKeyStatusRevoked = "revoked" // 已废弃（封号/手工吊销预留；自愈轮换走原行覆盖）
)

// UserVirtualKey 是每个 User 专属的 litellm virtual key（ADR-0014）。
//
// 网关用 Master Key 向 litellm 签出，转发推理时按用户注入，实现：A 归因（litellm 按 key/user_id 聚合每用户上游花费）、
// B 纵深防御（每把 key 带粗粒度 max_budget 保险丝，仅网关计量失效时兜底）。限额权威仍在网关侧滚动窗（ADR-0005/0008）。
//
// UserUUID uniqueIndex 落实 User:Key=1:1，任一时刻每用户只一把 active；轮换＝原行覆盖（保 1:1）。
// LitellmKey 明文落库为显式接受的安全权衡（内网可信 / DB 整体加密），等同上游凭证；将来可独立加 AES-GCM 层（ADR-0014）。
type UserVirtualKey struct {
	ID         int64  `json:"id" gorm:"column:id;type:bigserial;primaryKey;comment:自增ID"`
	UserUUID   string `json:"user_uuid" gorm:"column:user_uuid;type:varchar(50);not null;uniqueIndex;comment:所属用户UUID（1:1）"`
	LitellmKey string `json:"litellm_key" gorm:"column:litellm_key;type:varchar(255);not null;comment:完整litellm key（sk-...，转发注入用，明文）"`
	KeyAlias   string `json:"key_alias" gorm:"column:key_alias;type:varchar(100);not null;comment:litellm key 别名（user-{uuid}）"`
	TokenID    string `json:"token_id" gorm:"column:token_id;type:varchar(255);comment:litellm 返回的 token id（改/删引用）"`
	Status     string `json:"status" gorm:"column:status;type:varchar(20);not null;default:active;comment:状态 active/revoked"`
	CreatedAt  int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;comment:创建时间"`
	UpdatedAt  int64  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime;comment:更新时间"`
}

// TableName 表名。
func (UserVirtualKey) TableName() string {
	return "user_virtual_keys"
}
