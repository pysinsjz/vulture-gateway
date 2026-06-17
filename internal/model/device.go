package model

// Device 是一台被授权、绑定到 User 的 Desktop Agent 安装（见 CONTEXT.md）。
// 每次授权创建一个 Device，持有长期凭据（refresh 家族），可单独查看/吊销。
type Device struct {
	ID           int64  `json:"id" gorm:"column:id;type:bigserial;primaryKey;comment:自增ID"`
	UUID         string `json:"device_id" gorm:"column:uuid;type:varchar(50);not null;uniqueIndex;comment:对外 device_id"`
	UserUUID     string `json:"user_uuid" gorm:"column:user_uuid;type:varchar(50);not null;index;comment:所属 User"`
	Name         string `json:"name" gorm:"column:name;type:varchar(200);comment:设备名"`
	OS           string `json:"os" gorm:"column:os;type:varchar(100);comment:操作系统"`
	AppVersion   string `json:"app_version" gorm:"column:app_version;type:varchar(50);comment:App 版本"`
	CreatedAt    int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;comment:创建时间"`
	LastActiveAt int64  `json:"last_active_at" gorm:"column:last_active_at;comment:最近活跃时间（token 刷新时更新）"`
}

// TableName 表名。
func (Device) TableName() string {
	return "devices"
}
