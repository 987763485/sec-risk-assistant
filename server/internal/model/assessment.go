// Package model 的风险评估模型定义。
package model

import "time"

// RiskLevel 风险等级。
//
// 用字符串而不是 1–5 的整数，理由与 AssetStatus 一致：运维直接看库就能读懂。
// 但**等级与整数的对应关系是固定的**，前端画热力图时要按这个序排色阶：
//
//	very_high(5) > high(4) > medium(3) > low(2) > very_low(1)
//
// 这张对照表由 riskengine 与前端色板各持一份，两边都不做数值比较——
// 判定只发生在引擎里（docs/01 §2.6：风险计算只在后端实现）。
type RiskLevel string

const (
	// RiskLevelVeryHigh 很高
	RiskLevelVeryHigh RiskLevel = "very_high"
	// RiskLevelHigh 高
	RiskLevelHigh RiskLevel = "high"
	// RiskLevelMedium 中
	RiskLevelMedium RiskLevel = "medium"
	// RiskLevelLow 低
	RiskLevelLow RiskLevel = "low"
	// RiskLevelVeryLow 很低
	RiskLevelVeryLow RiskLevel = "very_low"
)

// RiskLevels 全部风险等级，**按严重程度从高到低**排列。
// 顺序即前端展示顺序，也是"从高到低判定阈值"这一规则的数据化表达。
var RiskLevels = []RiskLevel{
	RiskLevelVeryHigh, RiskLevelHigh, RiskLevelMedium, RiskLevelLow, RiskLevelVeryLow,
}

// Valid 判断风险等级是否合法。
func (l RiskLevel) Valid() bool {
	for _, v := range RiskLevels {
		if l == v {
			return true
		}
	}
	return false
}

// AssessmentStatus 评估任务状态。
type AssessmentStatus string

const (
	// AssessmentDraft 草稿：可以反复试算，但没有落库结果
	AssessmentDraft AssessmentStatus = "draft"
	// AssessmentCalculated 已计算：结果已落库，可下钻、可出报告
	AssessmentCalculated AssessmentStatus = "calculated"
)

// AssessmentScopeType 评估范围类型。
type AssessmentScopeType string

const (
	// ScopeAll 全部资产
	ScopeAll AssessmentScopeType = "all"
	// ScopeGroup 按资产组（含子组）
	ScopeGroup AssessmentScopeType = "group"
	// ScopeCustom 手工指定资产
	ScopeCustom AssessmentScopeType = "custom"
)

// AssessmentScopeTypes 全部合法的范围类型。
var AssessmentScopeTypes = []AssessmentScopeType{ScopeAll, ScopeGroup, ScopeCustom}

// Valid 判断范围类型是否合法。
func (s AssessmentScopeType) Valid() bool {
	for _, v := range AssessmentScopeTypes {
		if s == v {
			return true
		}
	}
	return false
}

// ThreatSource 风险项上威胁取值的来源。
const (
	// ThreatSourceDefault 取自评估任务级默认威胁
	ThreatSourceDefault = "default"
	// ThreatSourceManual 在风险项上逐项覆盖
	ThreatSourceManual = "manual"
)

// Assessment 评估任务。
//
// ConfigSnapshot 是这张表的核心（见迁移 000006 约束 1）：它把「算这次评估时
// 权重与阈值是多少」冻结在行内，改 system_configs 不会改写历史评估的档位。
type Assessment struct {
	ID          uint64              `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string              `gorm:"column:name;size:128"`
	Description string              `gorm:"column:description;size:512"`
	Status      AssessmentStatus    `gorm:"column:status;size:16"`
	ScopeType   AssessmentScopeType `gorm:"column:scope_type;size:16"`
	// ScopeRef 范围明细（JSON）：group 存组 ID 数组，custom 存资产 ID 数组。
	// 用 *string 而不是 json.RawMessage：空值必须是 SQL NULL，
	// 而不是会被 MySQL 拒绝的非法 JSON 空串（同 AuditLog.Detail 的理由）。
	ScopeRef *string `gorm:"column:scope_ref;type:json"`
	ModelKey string  `gorm:"column:model_key;size:64"`
	// DefaultThreatCode 任务级默认威胁。空串表示未指定，引擎按「中档」处理
	// （与 ImportanceDefault / SeverityDefault 同一原则：不填不等于最低）。
	DefaultThreatCode string  `gorm:"column:default_threat_code;size:64"`
	ConfigSnapshot    *string `gorm:"column:config_snapshot;type:json"`

	AssetsCount    uint32 `gorm:"column:assets_count"`
	RiskItemsCount uint32 `gorm:"column:risk_items_count"`
	// MaxRisk 可空：草稿状态下没有结果，NULL 表示「尚未计算」。
	// 用 0 当哨兵会让「算了但风险为 0」与「根本没算」无法区分。
	MaxRisk *float64 `gorm:"column:max_risk"`
	// LevelCounts 各等级条数（JSON），形如 {"very_high":2,"high":5,...}。
	LevelCounts  *string    `gorm:"column:level_counts;type:json"`
	CalculatedAt *time.Time `gorm:"column:calculated_at"`

	CreatedBy *uint64   `gorm:"column:created_by"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (Assessment) TableName() string { return "assessments" }

// RiskItem 风险项（资产 × 漏洞）。
//
// AssetID / VulnID 是**逻辑引用**，没有外键（见迁移 000006 约束 3）。
// 展示一律走快照列，跳转才用 ID —— 目标被删除时报告依然完整可读。
type RiskItem struct {
	ID           uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	AssessmentID uint64 `gorm:"column:assessment_id"`
	AssetID      uint64 `gorm:"column:asset_id"`
	VulnID       uint64 `gorm:"column:vuln_id"`

	// —— 快照列 ——
	AssetName       string `gorm:"column:asset_name;size:128"`
	AssetIP         string `gorm:"column:asset_ip;size:64"`
	VulnTitle       string `gorm:"column:vuln_title;size:255"`
	VulnCVEIDs      string `gorm:"column:vuln_cve_ids;size:512"`
	VulnSeverityRaw string `gorm:"column:vuln_severity_raw;size:64"`

	ThreatCode   string `gorm:"column:threat_code;size:64"`
	ThreatName   string `gorm:"column:threat_name;size:128"`
	ThreatSource string `gorm:"column:threat_source;size:16"`

	// Importance / Severity 是**原始档位**（1–5 整数），矩阵的横纵轴用它。
	// 用它们而不是 A / T / V：档位不受权重配置影响，改一次权重系数不会让
	// 矩阵里的格子整体位移——结构稳定，只有颜色变。
	Importance uint8 `gorm:"column:importance"`
	Severity   uint8 `gorm:"column:severity"`

	// A / T / V / R 四列齐存（见迁移 000006 约束 2）。
	AssetValueA  float64   `gorm:"column:asset_value_a"`
	ThreatWeight float64   `gorm:"column:threat_weight_t"`
	VulnWeight   float64   `gorm:"column:vuln_weight_v"`
	RiskValue    float64   `gorm:"column:risk_value_r"`
	RiskLevel    RiskLevel `gorm:"column:risk_level;size:16"`

	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (RiskItem) TableName() string { return "risk_items" }

// AssessmentAsset 资产级汇总。
//
// RiskValue 取该资产下**最严重**的一条风险项，不是平均值：一台机器能被打穿
// 到什么程度，由它最弱的那一环决定。
type AssessmentAsset struct {
	ID           uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	AssessmentID uint64 `gorm:"column:assessment_id"`
	AssetID      uint64 `gorm:"column:asset_id"`
	AssetName    string `gorm:"column:asset_name;size:128"`
	AssetIP      string `gorm:"column:asset_ip;size:64"`
	Importance   uint8  `gorm:"column:importance"`

	AssetValueA    float64   `gorm:"column:asset_value_a"`
	RiskValue      float64   `gorm:"column:risk_value"`
	RiskLevel      RiskLevel `gorm:"column:risk_level;size:16"`
	RiskItemsCount uint32    `gorm:"column:risk_items_count"`
	TopItemID      *uint64   `gorm:"column:top_item_id"`

	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (AssessmentAsset) TableName() string { return "assessment_assets" }
