// Package report 把评估结果渲染成可交付的报告文件（Word / Excel / PDF）。
//
// ▍边界
//
// 本包是**纯函数式**的：输入一个 ReportData，输出一段字节流。它不连数据库、
// 不判权限、不做风险计算——A / T / V / R 由 P4 的 riskengine 算好，由 service
// 层填进 ReportData 的数值字段。
//
// 这样切分有两个好处：
//
//  1. 渲染逻辑可以完全脱离 HTTP 与数据库做单测（解包 docx、读回 xlsx、
//     断言 HTML 转义）——报告渲染是最不适合「起个服务手工点一下」的代码，
//     因为它的产物是二进制，肉眼看不到内部结构。
//  2. 「报告里的数字从哪来」只有一个答案：外面填进来的。渲染器自己绝不
//     产生、也不修正任何数字。这是 P4 立下的「界面值 = 落库值 = 报告值」
//     三方等式在报告端的延续——渲染器一旦自己算，等式就失去意义。
//
// 依赖方向：service → report。report **不**反向依赖 service，
// 因此 ReportData 定义在这里，由 service 层负责映射。
package report

import (
	"fmt"
	"strconv"
	"time"
)

// Format 导出格式。
type Format string

const (
	// FormatWord Word（.docx），经 docgen 渲染
	FormatWord Format = "word"
	// FormatExcel Excel（.xlsx），本包用 excelize 直接生成
	FormatExcel Format = "excel"
	// FormatPDF PDF，本包渲染 HTML 后经 Gotenberg 转换
	FormatPDF Format = "pdf"
)

// ParseFormat 解析格式参数，未知格式返回错误。
//
// 大小写不敏感：前端下拉传的就是小写，但 curl 手工调试时经常会写成
// `--data '{"format":"PDF"}'`，为此拒掉一次合理的请求没有意义。
func ParseFormat(raw string) (Format, error) {
	switch Format(lower(raw)) {
	case FormatWord:
		return FormatWord, nil
	case FormatExcel:
		return FormatExcel, nil
	case FormatPDF:
		return FormatPDF, nil
	default:
		return "", fmt.Errorf("不支持的导出格式 %q（可选：word / excel / pdf）", raw)
	}
}

// Ext 返回扩展名（不含点）。
func (f Format) Ext() string {
	switch f {
	case FormatWord:
		return "docx"
	case FormatExcel:
		return "xlsx"
	case FormatPDF:
		return "pdf"
	default:
		return "bin"
	}
}

// ContentType 返回响应的 MIME 类型。
func (f Format) ContentType() string {
	switch f {
	case FormatWord:
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case FormatExcel:
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case FormatPDF:
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}

// Label 返回格式的中文名（用于文件名与审计明细）。
func (f Format) Label() string {
	switch f {
	case FormatWord:
		return "Word"
	case FormatExcel:
		return "Excel"
	case FormatPDF:
		return "PDF"
	default:
		return string(f)
	}
}

// LevelVeryHigh 等为风险等级码。
//
// 刻意用裸字符串而不是 import model：report 是纯渲染，让它不依赖任何业务
// 模型包，单测就只测排版、不牵动整个模型层。与 riskengine 是同一条理由。
const (
	LevelVeryHigh = "very_high"
	LevelHigh     = "high"
	LevelMedium   = "medium"
	LevelLow      = "low"
	LevelVeryLow  = "very_low"
)

// LevelOrder 全部等级，按严重程度从高到低。
//
// 报告里凡是「按等级」列出的地方都必须按这个顺序遍历，不能遍历 map——
// Go 的 map 顺序随机，同一份数据导两次会得到两个不同的表格。
var LevelOrder = []string{LevelVeryHigh, LevelHigh, LevelMedium, LevelLow, LevelVeryLow}

// LevelLabel 风险等级码 → 中文标签。
func LevelLabel(level string) string {
	switch level {
	case LevelVeryHigh:
		return "很高"
	case LevelHigh:
		return "高"
	case LevelMedium:
		return "中"
	case LevelLow:
		return "低"
	case LevelVeryLow:
		return "很低"
	default:
		return level
	}
}

// LevelAction 各等级的处置建议。
//
// 与阈值一样是**报告文案**而不是业务规则：它不参与任何判定，只决定
// 报告里「这一档该怎么办」那句话怎么写。
func LevelAction(level string) string {
	switch level {
	case LevelVeryHigh:
		return "立即整改，阻断上线"
	case LevelHigh:
		return "限期整改，纳入考核"
	case LevelMedium:
		return "计划整改，跟踪验证"
	case LevelLow:
		return "持续关注，择机处理"
	case LevelVeryLow:
		return "接受风险，记录备案"
	default:
		return ""
	}
}

// ScopeTypeLabel 范围类型 → 中文。
func ScopeTypeLabel(t string) string {
	switch t {
	case "all":
		return "全部资产"
	case "group":
		return "按资产组"
	case "custom":
		return "自定义选择"
	default:
		return t
	}
}

// ReportData 渲染一份报告所需的全部数据。
//
// 这是 report 包唯一的输入。字段都是「已定型的展示值」——渲染器直接
// 往模板里填，不做任何再加工。
type ReportData struct {
	// Title 报告标题（封面与页眉共用）
	Title string
	// Subtitle 副标题，可为空
	Subtitle string

	// GeneratedAt 报告生成时刻。与「计算时刻」不是一回事：
	// 报告可能在上次计算几天之后才导出，两个时间都必须出现在报告里，
	// 否则读报告的人无法判断结论的新鲜度。
	GeneratedAt time.Time
	// GeneratedBy 导出人登录名。
	//
	// 数据离开系统边界是敏感事件，报告自身也应该能回答「谁导出的」——
	// 不能只依赖审计日志，因为报告一旦被转发，审计日志就不在它身边了。
	GeneratedBy string

	Assessment AssessmentInfo
	Config     ConfigInfo

	// LevelCounts 五个等级的条数。key 为等级码，值必然存在（含 0）。
	LevelCounts map[string]int
	// MaxRisk 全量风险项里的最大 R
	MaxRisk float64

	Assets []AssetRow
	Items  []ItemRow

	// Matrix 5×5 风险矩阵，恒为 25 格。
	Matrix MatrixData
}

// AssessmentInfo 报告头部的评估任务信息。
type AssessmentInfo struct {
	ID                uint64
	Name              string
	Description       string
	ScopeType         string
	ScopeRef          []uint64
	DefaultThreatName string
	AssetsCount       int
	RiskItemsCount    int
	// CalculatedAt 上次计算的时刻（RFC3339 字符串，可为空）
	CalculatedAt string
}

// ConfigInfo 本次评估所用的配置。
//
// 它来自**评估的配置快照**而不是当前系统配置：报告必须能自证结论是按
// 哪套阈值算出来的，否则改一次阈值之后，所有旧报告都变得无法解释。
type ConfigInfo struct {
	Model       string
	AssetWeight float64
	Thresholds  Thresholds
	CapturedAt  time.Time
}

// Thresholds 四个档位下界（真实值）。
type Thresholds struct {
	VeryHigh int
	High     int
	Medium   int
	Low      int
}

// AssetRow 资产风险汇总的一行。
type AssetRow struct {
	Name       string
	IP         string
	Importance uint8
	ValueA     float64
	// RiskValue 该资产下最大的 R（不是平均值：一个致命漏洞就足以
	// 决定这台机器的处置优先级，平均会把它稀释掉）
	RiskValue  float64
	RiskLevel  string
	ItemsCount uint32
}

// ItemRow 风险项明细的一行。
type ItemRow struct {
	Seq        int
	AssetName  string
	AssetIP    string
	VulnTitle  string
	ThreatName string
	Importance uint8
	Severity   uint8
	A          float64
	T          float64
	V          float64
	R          float64
	RiskLevel  string
}

// MatrixCell 矩阵的一格。
type MatrixCell struct {
	Importance uint8
	Severity   uint8
	Count      int64
	MaxRisk    float64
	Level      string
}

// MatrixData 风险矩阵。
//
// GridSize 与 Cells 的长度由调用方保证（5 与 25），渲染器不再校验：
// 「矩阵恒为 25 格」是 riskengine 的约束，在这里再校验一遍只会让
// 两处规则各自演化。
type MatrixData struct {
	GridSize int
	Total    int64
	Cells    []MatrixCell
}

// Cell 按 (重要性, 严重程度) 取一格，取不到时返回零值格。
func (m MatrixData) Cell(importance, severity uint8) MatrixCell {
	for _, c := range m.Cells {
		if c.Importance == importance && c.Severity == severity {
			return c
		}
	}
	return MatrixCell{Importance: importance, Severity: severity}
}

// LevelCount 取某等级的条数。
func (d ReportData) LevelCount(level string) int { return d.LevelCounts[level] }

// ------------------------------------------------------------------ 表格行

// LevelRow 等级分布表的一行。
//
// ▍为什么把「行」抽成类型，而不让每个渲染器各自展开一遍
//
// Word 与 PDF 是两套渲染代码，但表格内容必须完全相同。如果各自写一遍
// 「遍历 LevelOrder、取计数、算占比」，那么将来任何一处改动（比如加一列
// 「累计占比」）都会只落在一边，而两份报告出现差异时，没有任何东西会报错
// —— 用户只会觉得"这两个文件好像不太一样"。
type LevelRow struct {
	Level   string
	Label   string
	Range   string
	Count   int
	Percent string
	Action  string
}

// LevelRows 返回五个等级的行，按严重程度从高到低。
func (d ReportData) LevelRows() []LevelRow {
	t := d.Config.Thresholds
	rows := make([]LevelRow, 0, len(LevelOrder))
	for _, level := range LevelOrder {
		rows = append(rows, LevelRow{
			Level:   level,
			Label:   LevelLabel(level),
			Range:   ThresholdRangeText(level, t),
			Count:   d.LevelCount(level),
			Percent: d.LevelPercent(level),
			Action:  LevelAction(level),
		})
	}
	return rows
}

// MatrixRow 矩阵表的一行：固定某个严重程度，横向铺开全部资产重要性。
type MatrixRow struct {
	Severity uint8
	Counts   []MatrixCell
	Levels   []string
}

// MatrixRows 返回矩阵的 5 行（纵轴为严重程度）。
func (d ReportData) MatrixRows() []MatrixRow {
	grid := d.GridSize()
	rows := make([]MatrixRow, 0, grid)
	for sev := 1; sev <= grid; sev++ {
		row := MatrixRow{Severity: uint8(sev)}
		for imp := 1; imp <= grid; imp++ {
			cell := d.Matrix.Cell(uint8(imp), uint8(sev))
			row.Counts = append(row.Counts, cell)
			row.Levels = append(row.Levels, LevelLabel(cell.Level))
		}
		rows = append(rows, row)
	}
	return rows
}

// GridSize 返回矩阵边长，异常时回落为 5。
func (d ReportData) GridSize() int {
	if d.Matrix.GridSize <= 0 {
		return 5
	}
	return d.Matrix.GridSize
}

// LevelTotal 全部等级条数之和（= 风险项总数）。
func (d ReportData) LevelTotal() int {
	var n int
	for _, level := range LevelOrder {
		n += d.LevelCounts[level]
	}
	return n
}

// LevelPercent 某等级占全部风险项的百分比，保留一位小数。
//
// 分母取 0 时返回 0：报告里「0 条风险项的评估」不该显示 NaN%。
func (d ReportData) LevelPercent(level string) string {
	total := d.LevelTotal()
	if total == 0 {
		return "0.0"
	}
	pct := float64(d.LevelCounts[level]) * 100 / float64(total)
	return strconv.FormatFloat(pct, 'f', 1, 64)
}

// ThresholdRangeText 生成某一档的区间文本。
//
// 区间是**闭在下界**的：判定从高到低逐个比较，R ≥ 20 即很高，
// 12 ≤ R < 20 即高。报告里必须把这个边界写法写清楚，否则读到 R=20 的人
// 会怀疑系统算错。
func ThresholdRangeText(level string, t Thresholds) string {
	switch level {
	case LevelVeryHigh:
		return fmt.Sprintf("R ≥ %d", t.VeryHigh)
	case LevelHigh:
		return fmt.Sprintf("%d ≤ R < %d", t.High, t.VeryHigh)
	case LevelMedium:
		return fmt.Sprintf("%d ≤ R < %d", t.Medium, t.High)
	case LevelLow:
		return fmt.Sprintf("%d ≤ R < %d", t.Low, t.Medium)
	case LevelVeryLow:
		return fmt.Sprintf("R < %d", t.Low)
	default:
		return ""
	}
}

// ------------------------------------------------------------------ 排版辅助

// Num 把数值格式化成报告里该有的样子。
//
// 用最短表示而不是固定小数位：
//
//	1     → "1"        （而不是 "1.000"）
//	10.5  → "10.5"
//	0.999 → "0.999"
//
// 这与 encoding/json 对 float64 的输出一致 —— 报告文本与 export-data
// 接口里的数字逐字相同，「报告值 = 落库值」在肉眼与脚本两个层面都成立。
func Num(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// Int 整数格式化（表格里的档位、条数）。
func Int(v int64) string { return strconv.FormatInt(v, 10) }

// lower 小写化（只处理 ASCII，避免引入 strings 只为一次转换）。
func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
