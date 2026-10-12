// Package model 的系统配置模型定义。
package model

import "time"

// 风险模型相关的配置键。集中定义避免各处手写字符串拼错——
// 拼错的键在 UPDATE 时表现为「影响 0 行」，而配置页会显示成「保存成功」。
const (
	// ConfigRiskModel 当前启用的风险模型（不可编辑）
	ConfigRiskModel = "risk.model"
	// ConfigRiskAssetWeight 资产价值权重系数
	ConfigRiskAssetWeight = "risk.asset_weight"
	// ConfigRiskThresholdVeryHigh 「很高」的阈值下界
	ConfigRiskThresholdVeryHigh = "risk.threshold.very_high"
	// ConfigRiskThresholdHigh 「高」的阈值下界
	ConfigRiskThresholdHigh = "risk.threshold.high"
	// ConfigRiskThresholdMedium 「中」的阈值下界
	ConfigRiskThresholdMedium = "risk.threshold.medium"
	// ConfigRiskThresholdLow 「低」的阈值下界
	ConfigRiskThresholdLow = "risk.threshold.low"
)

// RiskConfigKeys 风险模型配置键，按界面展示顺序排列。
var RiskConfigKeys = []string{
	ConfigRiskModel,
	ConfigRiskAssetWeight,
	ConfigRiskThresholdVeryHigh,
	ConfigRiskThresholdHigh,
	ConfigRiskThresholdMedium,
	ConfigRiskThresholdLow,
}

// SystemConfig 系统配置（KV 表）。
//
// 值的类型由 ValueType 描述（string / json / int / bool），但**存储一律是
// 文本**：一张 KV 表如果按类型分列存，就必须为每种类型写一套读写路径，
// 而配置项的读写频次低到不需要这种优化。类型信息只用于前端的控件选择。
type SystemConfig struct {
	ID          uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	ConfigKey   string `gorm:"column:config_key;size:128"`
	ConfigValue string `gorm:"column:config_value;type:text"`
	ValueType   string `gorm:"column:value_type;size:16"`
	Description string `gorm:"column:description;size:255"`
	// Editable 是否允许在界面修改。模型标识这类「代码认识它、用户不该改它」
	// 的配置为 false —— 只读展示比对着一个可改的输入框解释它为什么不能改要好。
	Editable  bool      `gorm:"column:editable"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (SystemConfig) TableName() string { return "system_configs" }
