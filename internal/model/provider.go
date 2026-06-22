package model

// Provider 渠道类别。Phase 1 仅 email/sms 两类（验证码下发）；oauth 预留给 Phase 3 社会化登录。
const (
	ProviderCategoryEmail = "email" // 邮件渠道（SMTP）
	ProviderCategorySMS   = "sms"   // 短信渠道
	ProviderCategoryOAuth = "oauth" // 第三方登录（Phase 3，预留）
)

// Provider 是认证相关的外部渠道/适配器配置（ADR-0013：字段对齐 Casdoor 核心列，便于未来迁移）。
// Phase 1 由 config 启动 seed 入库，不做后台 UI；未来 social 直接加行 + 搬 Casdoor 适配器。
type Provider struct {
	ID           int64  `json:"id" gorm:"column:id;type:bigserial;primaryKey;comment:自增ID"`
	UUID         string `json:"uuid" gorm:"column:uuid;type:varchar(50);not null;uniqueIndex;comment:对外唯一标识"`
	Name         string `json:"name" gorm:"column:name;type:varchar(100);not null;uniqueIndex;comment:渠道名（seed 唯一键）"`
	Category     string `json:"category" gorm:"column:category;type:varchar(20);not null;index;comment:类别 email/sms/oauth"`
	Type         string `json:"type" gorm:"column:type;type:varchar(50);not null;comment:具体厂商/协议，如 smtp/aliyun-sms"`
	ClientID     string `json:"client_id" gorm:"column:client_id;type:varchar(255);not null;default:'';comment:账号/AccessKey/SMTP 用户名"`
	ClientSecret string `json:"-" gorm:"column:client_secret;type:varchar(255);not null;default:'';comment:密钥/密码（机密，VG_ 注入 seed）"`
	Host         string `json:"host" gorm:"column:host;type:varchar(255);not null;default:'';comment:主机（SMTP host/短信网关）"`
	Port         int    `json:"port" gorm:"column:port;type:int;not null;default:0;comment:端口（SMTP port）"`
	Enabled      bool   `json:"enabled" gorm:"column:enabled;not null;default:true;comment:是否启用"`
	CreatedAt    int64  `json:"created_at" gorm:"column:created_at;autoCreateTime;comment:创建时间"`
	UpdatedAt    int64  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime;comment:更新时间"`
}

// TableName 表名。
func (Provider) TableName() string {
	return "providers"
}
