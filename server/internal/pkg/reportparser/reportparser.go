// Package reportparser 把扫描报告文件解析成漏洞清单。
//
// 三种格式各有一个实现，全部实现同一个 Parser 接口：
// service 层只面对接口，将来加 Qualys / 绿盟报告时不动调用方。
//
// 安全约定（对应 docs/05 遗留到 P3 的「解析器 XXE / DoS」项）：
//   - 一律使用标准库 encoding/xml。它**不支持解析外部实体**（external
//     DTD 的 SYSTEM 实体直接报错），传统 XXE 的文件读取 / SSRF 路径
//     在这里根本不存在；
//   - 实体膨胀（billion laughs）由两道闸挡住：调用方先做体积上限检查，
//     标准库对未定义实体的递归展开会以错误终止解析；
//   - 单个报告的漏洞条数上限 MaxVulns，超限直接失败而不是默默截断——
//     截断后的清单会让用户以为「这台机器只有这么多漏洞」。
package reportparser

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"secrisk/server/internal/model"
)

// MaxVulns 单个报告的漏洞条数上限。
//
// 与 pkg/spreadsheet.MaxRows 同数量级：一个 5000 条漏洞的报告已经
// 远超单次评估的合理规模，超过这个数大概率是格式解析错了（比如把
// 同一条目重复展开），停下来报错比写进去更负责。
const MaxVulns = 5000

// ErrNoVulns 报告里没有解析出任何漏洞条目。
var ErrNoVulns = errors.New("reportparser: 报告里没有漏洞条目")

// ErrTooManyVulns 报告的漏洞条数超过上限。
var ErrTooManyVulns = errors.New("reportparser: 漏洞条数超过上限")

// ErrMalformed 报告内容损坏（不是合法 XML / 关键元素缺失）。
var ErrMalformed = errors.New("reportparser: 报告内容无法解析")

// ParsedVuln 解析出的一条漏洞。字段与 model.Vulnerability 对齐，
// 但不直接复用模型——解析层不该知道 GORM 的存在。
type ParsedVuln struct {
	Title       string
	CVEIDs      []string
	SeverityRaw string
	Severity    uint8
	Description string
	Solution    string
	HostIP      string
	Hostname    string // 仅供参考（进 description 的补充），不参与自动关联
	Port        *uint16
	Protocol    string
	Service     string
}

// RowError Excel 路径的行级错误（XML 路径结构简单，整体报错即可）。
//
// 行号是**源文件行号**（含表头、从 1 开始），与资产导入的口径一致：
// 用户拿错误对着自己手里的文件找，偏移一行的报错等于没报。
type RowError struct {
	Row     int    `json:"row"`
	Column  string `json:"column"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ParseResult 一次解析的完整产出。
type ParseResult struct {
	Format model.ScanFileFormat
	Vulns  []ParsedVuln
	// Errors Excel 路径的行级错误。非空时调用方（service）不得 commit。
	Errors []RowError
	// MissingColumns Excel 缺失的必需列。非空时同样不得 commit。
	MissingColumns []string
}

// Parser 扫描报告解析器接口。
type Parser interface {
	// Format 本解析器对应的格式标识。
	Format() model.ScanFileFormat
	// Detect 判断数据是否属于本格式。
	//
	// 只允许做前缀嗅探（魔数 / 根元素名），不做完整解析——
	// Detect 在上传与解析两个阶段都会被调用，重复全量解析是浪费；
	// 而且「嗅探说像、解析说不像」时应当报 ErrMalformed 而不是换解析器，
	// 把一个损坏的 Nessus 报告交给 Excel 解析器只会得到更混乱的报错。
	Detect(data []byte) bool
	// Parse 完整解析。
	Parse(data []byte) (*ParseResult, error)
}

// parsers 全部解析器。Detect 的调用顺序即判定顺序，两个都命中时
// 取先者——目前三种格式的根元素互不重叠，顺序只影响可读性。
var parsers = []Parser{&NessusParser{}, &OpenVASParser{}, &ExcelParser{}}

// Parse 用首个 Detect 命中的解析器解析数据。
//
// data 必须已经过体积上限检查（上传阶段做），本包不再重复限制，
// 但漏洞条数上限在任何路径都生效。
func Parse(data []byte) (*ParseResult, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrNoVulns
	}
	for _, p := range parsers {
		if !p.Detect(data) {
			continue
		}
		res, err := p.Parse(data)
		if err != nil {
			return nil, err
		}
		res.Format = p.Format()
		if err := validateResult(res); err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, fmt.Errorf("%w: 无法识别的报告格式", ErrMalformed)
}

// DetectFormat 返回首个认领该内容的解析器格式；都不认领时返回空串。
//
// 供上传阶段把 format 写进 scan_files（提前给出格式提示），
// 也供 service 在解析失败时把「哪个格式解析失败」写进日志。
func DetectFormat(data []byte) model.ScanFileFormat {
	for _, p := range parsers {
		if p.Detect(data) {
			return p.Format()
		}
	}
	return ""
}

// validateResult 统一校验解析产出：条数上限与「一条都没有」。
//
// Excel 路径的行级错误不算「没有条目」——有错误行时 service 会把
// 错误表渲染给用户，错误信息里已经包含「没有可导入的行」这层含义。
func validateResult(res *ParseResult) error {
	if len(res.Errors) > 0 || len(res.MissingColumns) > 0 {
		return nil
	}
	if len(res.Vulns) == 0 {
		return ErrNoVulns
	}
	if len(res.Vulns) > MaxVulns {
		return fmt.Errorf("%w: %d 条（上限 %d）", ErrTooManyVulns, len(res.Vulns), MaxVulns)
	}
	return nil
}

// ------------------------------------------------------------------ 通用工具

// severityFromCVSS 把 0.0–10.0 的 CVSS 分值映射到 1–5。
//
// 切档点与业界惯例一致（≥9 严重 / ≥7 高 / ≥4 中 / >0 低 / 0 信息）。
// Out of range 的分值一律钳到边界——扫描器给 12.0 不构成拒绝解析的理由。
func severityFromCVSS(score float64) uint8 {
	switch {
	case score >= 9.0:
		return 5
	case score >= 7.0:
		return 4
	case score >= 4.0:
		return 3
	case score > 0:
		return 2
	default:
		return 1
	}
}

// SeverityFromWord 把常见等级词映射到 1–5，供手工录入复用解析器口径。
func SeverityFromWord(s string) (uint8, bool) { return severityFromWord(s) }

// severityFromWord 把常见等级词映射到 1–5。
//
// 中英文都收：通用 Excel 清单的「严重程度」列既可能写「高」也可能写
// High，查表比对一次的成本可以忽略，识别率却明显更高。
func severityFromWord(s string) (uint8, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	// 「危急」与「高危/中危/低危」这一组要一起收：中危、低危早就在表里，
	// 唯独漏了「高危」—— 而它恰恰是中文报告里最常见的一种写法。
	// 漏掉的后果不是报错而是**静默降级**：整表按默认「中危」入库，
	// 高危漏洞被系统性低估，且没有任何提示。对称性在查表里就是正确性。
	case "critical", "严重", "危急", "5":
		return 5, true
	case "high", "高危", "高", "4":
		return 4, true
	case "medium", "medium risk", "中", "中危", "3":
		return 3, true
	case "low", "低", "低危", "2":
		return 2, true
	case "info", "informational", "none", "信息", "提示", "1":
		return 1, true
	default:
		return 0, false
	}
}

// splitPortSpec 解析 OpenVAS 的端口描述（"443/tcp" / "general/tcp"）。
//
// 返回端口（nil = 与端口无关）、协议。解析不了时协议仍尽量保留。
func splitPortSpec(spec string) (*uint16, string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, ""
	}
	parts := strings.SplitN(spec, "/", 2)
	proto := ""
	if len(parts) == 2 {
		proto = strings.ToLower(strings.TrimSpace(parts[1]))
	}
	var port *uint16
	var p uint16
	if _, err := fmt.Sscanf(parts[0], "%d", &p); err == nil && p > 0 {
		port = &p
	}
	return port, proto
}
