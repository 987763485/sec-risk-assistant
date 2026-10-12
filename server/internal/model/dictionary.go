package model

import "time"

// DictionaryCategory 字典类别。
//
// 四类的 weight 语义并不相同，这需要在读写两侧都说清楚：
//
//	asset_type     资产类型     weight 不参与风险计算，恒为 1
//	threat         威胁         weight = 威胁发生可能性 T（1–5）
//	vulnerability  脆弱性       weight = 脆弱性严重程度 V（1–5）
//	measure        已有措施     weight = 防护有效性（1–5，越大越好）
//
// 之所以共用一列而不是给每类单开一列：四类除权重外的结构与增删改查行为
// 完全一致，合成一张表让「字典维护」页只需要一套 CRUD。
// 代价是这一列承载了四种语义，因此**必须**靠这份注释与 docs/04 交代清楚。
type DictionaryCategory string

const (
	// CategoryAssetType 资产类型
	CategoryAssetType DictionaryCategory = "asset_type"
	// CategoryThreat 威胁
	CategoryThreat DictionaryCategory = "threat"
	// CategoryVulnerability 脆弱性
	CategoryVulnerability DictionaryCategory = "vulnerability"
	// CategoryMeasure 已有措施
	CategoryMeasure DictionaryCategory = "measure"
)

// AllDictionaryCategories 全部字典类别，顺序即界面分栏顺序。
var AllDictionaryCategories = []DictionaryCategory{
	CategoryAssetType, CategoryThreat, CategoryVulnerability, CategoryMeasure,
}

// Valid 判断类别是否合法。
func (c DictionaryCategory) Valid() bool {
	for _, v := range AllDictionaryCategories {
		if c == v {
			return true
		}
	}
	return false
}

// ParticipatesInRiskCalculation 判断该类别的权重是否参与风险计算。
//
// asset_type 的权重是唯一一个「写了也没用」的值，服务层用它来决定
// 是否对权重做区间校验，也用它给接口的说明文案兜底。
func (c DictionaryCategory) ParticipatesInRiskCalculation() bool {
	return c != CategoryAssetType
}

// Dictionary 业务字典项。
//
// Weight 是「类别相关的数值属性」，语义由 Category 决定（见上方说明）。
// Code 创建后不可变：资产表按码引用字典，改码会让历史资产指不到东西。
type Dictionary struct {
	ID       uint64             `gorm:"column:id;primaryKey;autoIncrement"`
	Category DictionaryCategory `gorm:"column:category;size:32"`
	Code     string             `gorm:"column:code;size:64"`
	Name     string             `gorm:"column:name;size:128"`
	// Weight 用 float64 承载 DECIMAL(6,3)：3 位小数远超实际需要，
	// 而风险计算的精度要求并不苛刻，用浮点不会引入可观察的偏差。
	Weight      float64 `gorm:"column:weight"`
	Description string  `gorm:"column:description;size:255"`
	IsBuiltin   bool    `gorm:"column:is_builtin"`
	// Enabled 停用后不再出现在新建表单，但历史数据引用它时仍能翻译出中文名。
	// 「停用」与「删除」的区别就在这里，详见 docs/04。
	Enabled   bool      `gorm:"column:enabled"`
	SortOrder int       `gorm:"column:sort_order"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (Dictionary) TableName() string { return "dictionaries" }
