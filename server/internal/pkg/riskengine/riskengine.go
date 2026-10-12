// Package riskengine 实现 GB/T 20984 相乘法的风险值计算。
//
// ▍这个包存在的唯一理由
//
// docs/01 §2.6 立了一条铁律：**风险计算只在后端实现，前端经接口取值**。
// 于是「试算（preview）」「落库（calculate）」「导出报告（export-data）」
// 三条路径必须给出完全一致的数字。做法不是三处各写一遍再对数，而是让它们
// 共用这一个包——只要存在第二条计算路径，三处一致迟早会被改配置的操作打破。
//
// ▍为什么全是定点整数
//
// R = A × T × V 要参与阈值比较（≥20 / ≥12 / ≥6 / ≥2）。浮点表示误差落在
// 阈值边界上，得到的就是一条错误的等级——比如 12.000000000000002 与
// 11.999999999999998 会分别判成「高」与「中」，而它们在数学上是同一个数。
// 这类错误不报错、不告警，只在某个特定的权重组合下出现一次。
// 因此内部一律把数值放大 1000 倍走 int64，阈值同样放大后比较，
// 只在结果出参时除回 Scale。
//
// 缩放倍数取 1000（而不是 100 或 10000）：权重与阈值在 system_configs 里
// 就是 DECIMAL(6,3)，三位小数是配置的精度上限，再放大只是徒增溢出风险。
package riskengine

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// Scale 定点放大倍数。
//
// 与 DECIMAL(6,3) 的三位小数对应，改动它会同时改变阈值含义与所有历史
// 评估的可复现性——除非配套迁移，否则不要动。
const Scale int64 = 1000

// Name 模型标识，与 system_configs 的 risk.model 对应。
const Name = "gb_t_20984_multiplication"

// 档位取值范围（含两端）。A / V 的档位就是资产重要性与漏洞严重程度。
const (
	// MinGrade 档位下限
	MinGrade = 1
	// MaxGrade 档位上限
	MaxGrade = 5
	// GridSize 矩阵边长：5×5 的横纵轴都是 1–5。
	GridSize = MaxGrade - MinGrade + 1
)

// DefaultThreatWeight 未指定威胁时的 T 值。
//
// 取中档 3.000 而不是最低档：与 ImportanceDefault / SeverityDefault 同一条
// 原则——「不填」不等于「最低」，否则漏配威胁会系统性低估全部风险。
const DefaultThreatWeight = 3.0

// 风险等级。与 model.RiskLevel 的字符串取值一一对应。
//
// 这里刻意用裸字符串而不是 import model：riskengine 是纯计算，
// 让它不依赖任何业务模型包，单元测试就能只测数学、不牵动整个模型层。
// 两边的一致性由 service 层的显式映射保证（见 service/assessment.go）。
const (
	LevelVeryHigh = "very_high"
	LevelHigh     = "high"
	LevelMedium   = "medium"
	LevelLow      = "low"
	LevelVeryLow  = "very_low"
)

// Levels 全部等级，按严重程度从高到低排列。
var Levels = []string{LevelVeryHigh, LevelHigh, LevelMedium, LevelLow, LevelVeryLow}

// LevelRank 返回等级的序数（越高越严重），未知等级返回 0。
func LevelRank(level string) int {
	for i, l := range Levels {
		if l == level {
			return len(Levels) - i
		}
	}
	return 0
}

// Config 一次计算所用的权重与阈值，全部为放大 Scale 倍的定点整数。
//
// 它的来源是 system_configs，但**传入计算的一定是快照**而不是「当前配置」：
// 历史评估必须在配置改动后仍然可复现（见迁移 000006 约束 1）。
type Config struct {
	// AssetWeight 资产价值权重系数（默认 1.000）
	AssetWeight int64
	// VeryHigh / High / Medium / Low 四个档位下界，必须严格递减且 Low ≥ 1。
	VeryHigh int64
	High     int64
	Medium   int64
	Low      int64
}

// DefaultConfig 返回出厂配置：与迁移 000001 预置的 system_configs 一致。
//
// 它有两个用途：单元测试的基准，以及配置读取失败时的兜底（宁可算出结果
// 再报配置异常，也不要让整个评估页白屏）。
func DefaultConfig() Config {
	return Config{
		AssetWeight: 1 * Scale,
		VeryHigh:    20 * Scale,
		High:        12 * Scale,
		Medium:      6 * Scale,
		Low:         2 * Scale,
	}
}

// ParseConfig 由人类可读的数值构建配置。
//
// assetWeight 与三个阈值都按「真实值」传（如 1.0 / 20），内部统一放大。
// 解析失败与配置自相矛盾都返回错误——**在加载时就拒绝**，而不是算出一个
// 自相矛盾的等级后再让人回头找原因。
func ParseConfig(assetWeight float64, veryHigh, high, medium, low int) (Config, error) {
	if math.IsNaN(assetWeight) || math.IsInf(assetWeight, 0) {
		return Config{}, errors.New("资产价值权重系数不是有效数字")
	}
	cfg := Config{
		AssetWeight: milli(assetWeight),
		VeryHigh:    int64(veryHigh) * Scale,
		High:        int64(high) * Scale,
		Medium:      int64(medium) * Scale,
		Low:         int64(low) * Scale,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate 校验配置自洽性。
//
// 三条规则各有明确后果：
//   - 权重必须为正，否则 A 变成 0 或负数，全部风险落在「很低」；
//   - 四个阈值必须**严格递减**，相等会让中间那一档永远判不出来
//     （判定从高到低，先命中的先返回）；
//   - 最低阈值必须 ≥ 1，等于 0 会让「很低」这一档永远为空。
func (c Config) Validate() error {
	if c.AssetWeight <= 0 {
		return errors.New("资产价值权重系数必须大于 0")
	}
	if c.AssetWeight > 100*Scale {
		return errors.New("资产价值权重系数不得超过 100")
	}
	if !(c.VeryHigh > c.High && c.High > c.Medium && c.Medium > c.Low) {
		return fmt.Errorf("风险等级阈值必须严格递减（很高 > 高 > 中 > 低），当前为 %s > %s > %s > %s",
			v(c.VeryHigh), v(c.High), v(c.Medium), v(c.Low))
	}
	if c.Low < 1*Scale {
		return errors.New("「低」的下界必须不小于 1，否则「很低」这一档永远为空")
	}
	return nil
}

// Thresholds 返回四个阈值的真实值，缺省用于快照与展示。
func (c Config) Thresholds() Thresholds {
	return Thresholds{
		VeryHigh: int(c.VeryHigh / Scale),
		High:     int(c.High / Scale),
		Medium:   int(c.Medium / Scale),
		Low:      int(c.Low / Scale),
	}
}

// AssetWeightValue 返回权重系数的真实值。
func (c Config) AssetWeightValue() float64 { return float64(c.AssetWeight) / float64(Scale) }

// Input 一条风险项的计算输入。
type Input struct {
	// Importance 资产重要性原始档位 1–5（对应 A）
	Importance uint8
	// ThreatWeight 威胁权重 T（来自 dictionaries，默认 DefaultThreatWeight）
	ThreatWeight float64
	// Severity 漏洞严重程度原始档位 1–5（对应 V）
	Severity uint8
}

// Result 一条风险项的计算结果。
//
// 四个中间量一并返回，是因为**调用方要把它们原样落库**——
// 下钻时用户问「这台机器为什么是 20 分」，答案必须能当场拆出来。
type Result struct {
	A     float64
	T     float64
	V     float64
	R     float64
	Level string
}

// Compute 计算单条风险项。
//
// R = A × T × V，其中 A = 重要性 × 资产价值权重系数。
//
// 全程 int64：先把每个因子放大 Scale 倍，乘完再逐级除回，避免中间结果
// 溢出（int64 上限约 9.2×10^18，而最坏中间量约 1.25×10^11）。
func Compute(cfg Config, in Input) Result {
	aWeighted := int64(in.Importance) * cfg.AssetWeight // importance × wA × Scale
	tMilli := milli(in.ThreatWeight)
	vMilli := int64(in.Severity) * Scale

	rMilli := aWeighted * tMilli / Scale * vMilli / Scale

	return Result{
		A:     float64(aWeighted) / float64(Scale),
		T:     float64(tMilli) / float64(Scale),
		V:     float64(vMilli) / float64(Scale),
		R:     float64(rMilli) / float64(Scale),
		Level: LevelOf(cfg, rMilli),
	}
}

// LevelOf 按阈值判定等级，**从高到低**逐个比较。
//
// 顺序不能反：从低到高判会让所有结果都落在最低档（第一个条件就命中）。
func LevelOf(cfg Config, rMilli int64) string {
	switch {
	case rMilli >= cfg.VeryHigh:
		return LevelVeryHigh
	case rMilli >= cfg.High:
		return LevelHigh
	case rMilli >= cfg.Medium:
		return LevelMedium
	case rMilli >= cfg.Low:
		return LevelLow
	default:
		return LevelVeryLow
	}
}

// LevelOfValue 按真实值判定等级（供 service 层对已落库的 R 复核档位）。
func LevelOfValue(cfg Config, r float64) string {
	return LevelOf(cfg, milli(r))
}

// Thresholds 四个阈值的真实值。
type Thresholds struct {
	VeryHigh int `json:"very_high"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Snapshot 配置快照的 JSON 形态，存进 assessments.config_snapshot。
//
// 存「人类可读的真实值」而不是定点整数：快照是给人看的证据，
// 一份 {“asset_weight”:1.0,“thresholds”:{"very_high":20,...}} 任何人
// 打开数据库都能读懂，而定点整数还需要知道 Scale 才解释得通。
type Snapshot struct {
	Model       string     `json:"model"`
	AssetWeight float64    `json:"asset_weight"`
	Thresholds  Thresholds `json:"thresholds"`
	// CapturedAt 快照时间。有了它，「这份评估比那次改配置早还是晚」
	// 这个问题不需要去翻审计日志。
	CapturedAt time.Time `json:"captured_at"`
}

// SnapshotOf 由配置构造快照。
func SnapshotOf(cfg Config, capturedAt time.Time) Snapshot {
	return Snapshot{
		Model:       Name,
		AssetWeight: cfg.AssetWeightValue(),
		Thresholds:  cfg.Thresholds(),
		CapturedAt:  capturedAt,
	}
}

// milli 把真实值放大成定点整数，四舍五入到 1/1000。
func milli(f float64) int64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(math.Round(f * float64(Scale)))
}

// v 把定点整数还原成日志里可读的真实值。
func v(m int64) string {
	return fmt.Sprintf("%g", float64(m)/float64(Scale))
}
