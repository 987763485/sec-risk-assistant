// Package model 的资产与资产组模型定义。
//
// 命名与可空性约定沿用 user.go 的规则：
// 可空列一律用指针（*string / *uint16），避免零值被当成真实数据写进去。
package model

import "time"

// AssetStatus 资产状态。
//
// 用字符串而不是枚举整数：可读性上的收益很直接——运维直接看库就能读懂，
// 而整数枚举需要一份对照表才能解读，那份对照表迟早会和代码漂移。
// （与 users.status 的选择一致。）
type AssetStatus string

const (
	// AssetStatusInUse 在用
	AssetStatusInUse AssetStatus = "in_use"
	// AssetStatusIdle 闲置
	AssetStatusIdle AssetStatus = "idle"
	// AssetStatusOffline 已下线
	AssetStatusOffline AssetStatus = "offline"
	// AssetStatusScrapped 已报废。**资产退役请用这个状态，不要删除。**
	// 台账的价值在于「这台机器曾经存在、已于某时退役」，删掉就丢掉了一段事实。
	AssetStatusScrapped AssetStatus = "scrapped"
)

// AssetStatuses 全部合法状态，顺序即界面展示顺序。
var AssetStatuses = []AssetStatus{
	AssetStatusInUse, AssetStatusIdle, AssetStatusOffline, AssetStatusScrapped,
}

// Valid 判断状态值是否合法。
func (s AssetStatus) Valid() bool {
	for _, v := range AssetStatuses {
		if s == v {
			return true
		}
	}
	return false
}

// 资产重要性（对应风险模型里的资产价值 A）的取值范围，含两端。
const (
	ImportanceMin uint8 = 1
	ImportanceMax uint8 = 5
	// ImportanceDefault 未填写时的默认值：中档，避免「不填就等于最低价值」
	// 这种会让资产被系统性低估的隐式默认。
	ImportanceDefault uint8 = 3
)

// ValidImportance 判断重要性取值是否在合法区间内。
func ValidImportance(v uint8) bool {
	return v >= ImportanceMin && v <= ImportanceMax
}

// AssetGroup 资产组（层级树的一个节点）。
//
// Path 是**物化路径**，形如 /1/4/9/，末尾带斜杠且包含自身。
// 选它而不是递归 CTE 的理由：子树查询是高频操作，物化路径把它变成一条
// `WHERE path LIKE '/1/4/%'` 的索引扫描；代价是移动节点要重写整棵子树，
// 但那是服务层一条 UPDATE 就能完成的事（见 repository/assetgroup.go）。
type AssetGroup struct {
	ID       uint64  `gorm:"column:id;primaryKey;autoIncrement"`
	ParentID *uint64 `gorm:"column:parent_id"`
	// ParentKey 由数据库生成（IFNULL(parent_id, 0)），Go 侧只读不写。
	// 它的存在只为让 (parent_key, name) 这个唯一索引对根组也生效——
	// MySQL 的唯一索引把多个 NULL 视为互不相同，直接对 parent_id 建索引
	// 拦不住根组重名（与 users.email 是同一个陷阱）。
	ParentKey   *uint64   `gorm:"column:parent_key;->"`
	Name        string    `gorm:"column:name;size:64"`
	Path        string    `gorm:"column:path;size:512"`
	Depth       uint32    `gorm:"column:depth"`
	Description string    `gorm:"column:description;size:255"`
	SortOrder   int       `gorm:"column:sort_order"`
	CreatedBy   *uint64   `gorm:"column:created_by"`
	CreatedAt   time.Time `gorm:"column:created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (AssetGroup) TableName() string { return "asset_groups" }

// MaxAssetGroupDepth 资产组最大层级深度（根组为 1 层）。
//
// 限制存在的两个理由：物化路径列只有 512 字符，深度无上限最终会写不进去；
// 更重要的是超过七八层的资产分组在实践里已经没人能说清它的含义，
// 与其让它悄悄长出二十层，不如在第八层就报错。
const MaxAssetGroupDepth = 8

// Asset 资产台账。
//
// AssetType 与 Status 存的都是**码**（字符串），不是字典表主键 id。
// 这样历史资产不会因为字典行被重排而指向别的类型，资产表也能脱离
// 字典表被单独读懂。代价是字典项的 code 创建后不可变。
type Asset struct {
	ID uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	// AssetNo 资产编号（业务编号）。可空：唯一索引下多个 NULL 互不冲突，
	// 因此「未编号」的资产可以有很多条；若用空串就会互相冲突。
	AssetNo   *string `gorm:"column:asset_no;size:64"`
	Name      string  `gorm:"column:name;size:128"`
	AssetType string  `gorm:"column:asset_type;size:32"`
	GroupID   *uint64 `gorm:"column:group_id"`
	IPAddress string  `gorm:"column:ip_address;size:64"`
	// Port 可空：NULL 表示「未填写」，0 不是合法端口，不能拿它当哨兵值。
	Port        *uint16     `gorm:"column:port"`
	Hostname    string      `gorm:"column:hostname;size:128"`
	OSType      string      `gorm:"column:os_type;size:64"`
	Importance  uint8       `gorm:"column:importance"`
	Owner       string      `gorm:"column:owner;size:64"`
	Department  string      `gorm:"column:department;size:64"`
	Status      AssetStatus `gorm:"column:status;size:16"`
	Tags        string      `gorm:"column:tags;size:255"`
	Description string      `gorm:"column:description;size:512"`
	CreatedBy   *uint64     `gorm:"column:created_by"`
	CreatedAt   time.Time   `gorm:"column:created_at"`
	UpdatedAt   time.Time   `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (Asset) TableName() string { return "assets" }

// AssetNoValue 返回资产编号字符串（未填时为空串），便于直接参与 JSON 序列化。
func (a *Asset) AssetNoValue() string {
	if a.AssetNo == nil {
		return ""
	}
	return *a.AssetNo
}

// PortValue 返回端口（未填时为 0）。
//
// 注意这个 0 只用于展示层（前端显示为「—」），**不能**回写到数据库：
// 数据库里「未填」必须保持 NULL。
func (a *Asset) PortValue() uint16 {
	if a.Port == nil {
		return 0
	}
	return *a.Port
}
