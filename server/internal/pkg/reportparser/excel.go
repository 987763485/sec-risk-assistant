package reportparser

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/spreadsheet"
)

// ExcelParser 解析通用表格漏洞清单（xlsx / csv）。
//
// 与资产导入同构的列头映射：按**列名**定位而不是按列序——
// 用户手里的清单可能来自其他工具的导出，列序不可控；
// 列名是我们模板里印着的，认列名才有「照着模板改就能过」的确定性。
type ExcelParser struct{}

// Format 实现接口。
func (ExcelParser) Format() model.ScanFileFormat { return model.ScanFormatExcel }

// vulnColumn 漏洞模板的列定义。顺序即模板列序。
type vulnColumn struct {
	Header   string
	Key      string
	Required bool
	MaxRunes int
	// Note / Width 模板「填写说明」表用。
	Note  string
	Width float64
}

// vulnColumns 漏洞清单的列定义。
//
// 只有「漏洞名称」必填：主机 IP 留空表示漏洞与具体主机无关
// （比如一条制度类发现），强制它会把合法数据拒之门外。
var vulnColumns = []vulnColumn{
	{Header: "漏洞名称", Key: "title", Required: true, MaxRunes: 255,
		Note: "漏洞的显示名称，最多 255 字", Width: 36},
	{Header: "CVE编号", Key: "cve", MaxRunes: 512,
		Note: "多个 CVE 用英文逗号分隔，留空表示无", Width: 24},
	{Header: "严重程度", Key: "severity", MaxRunes: 32,
		Note: "严重/高/中/低/信息 或 Critical/High/Medium/Low/Info 或 1–5 或 CVSS 分值；留空按 中 处理", Width: 12},
	{Header: "主机IP", Key: "host_ip", MaxRunes: 64,
		Note: "受影响主机的 IP，用于自动关联资产台账；留空表示与具体主机无关", Width: 18},
	{Header: "端口", Key: "port",
		Note: "1–65535 的整数，留空表示与端口无关", Width: 10},
	{Header: "协议", Key: "protocol", MaxRunes: 16,
		Note: "tcp / udp，留空表示未注明", Width: 10},
	{Header: "服务", Key: "service", MaxRunes: 64,
		Note: "服务名，如 https / ssh", Width: 12},
	{Header: "漏洞描述", Key: "description", MaxRunes: 2000,
		Note: "漏洞的技术描述", Width: 48},
	{Header: "修复建议", Key: "solution", MaxRunes: 2000,
		Note: "修复方式或缓解措施", Width: 48},
}

// Detect 实现接口。
//
// 放在判定顺序的最后：PK 魔数（xlsx）不会与 XML 混淆，
// 但 CSV 与 XML 都是文本，必须先让两个 XML 解析器认领，
// 剩下的文本才轮到 CSV。表格是模板还是用户自制的清单都按列头走。
func (ExcelParser) Detect(data []byte) bool {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}) {
		return true // xlsx
	}
	// XML 根元素在 < 尾随白名单之后出现；前面两个解析器没认领的
	// `<?xml` 开头内容不该被当成 CSV 去逐行读。
	trimmed := bytes.TrimLeft(data[:min(len(data), 128)], " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] != '<'
}

// Parse 实现接口。
func (ExcelParser) Parse(data []byte) (*ParseResult, error) {
	// MaxVulns+1：多读一行才能区分「正好 N 条」与「超过 N 条」，
	// 与 handler 读上传流时多读 1 字节是同一个技巧。
	sheet, err := spreadsheet.Read(data, MaxVulns+1)
	if err != nil {
		switch {
		case errors.Is(err, spreadsheet.ErrEmpty):
			return nil, ErrNoVulns
		case errors.Is(err, spreadsheet.ErrTooLarge):
			return nil, fmt.Errorf("%w: 文件体积超限", ErrMalformed)
		default:
			return nil, fmt.Errorf("%w: %s", ErrMalformed, err)
		}
	}
	if len(sheet.Rows) == 0 {
		return nil, ErrNoVulns
	}

	header := sheet.Rows[0]
	index := make(map[string]int, len(header.Cells))
	for i, cell := range header.Cells {
		name := strings.TrimSpace(cell)
		if name != "" {
			index[name] = i
		}
	}

	// 必需列缺失时立即报错：此时逐行校验的报错全是「找不到列」的变体，
	// 让用户先补列再改数据。
	var missing []string
	for _, col := range vulnColumns {
		if col.Required {
			if _, ok := index[col.Header]; !ok {
				missing = append(missing, col.Header)
			}
		}
	}
	if len(missing) > 0 {
		return &ParseResult{MissingColumns: missing}, nil
	}

	at := func(key string) (vulnColumn, int, bool) {
		for _, col := range vulnColumns {
			if col.Key == key {
				if i, ok := index[col.Header]; ok {
					return col, i, true
				}
				return col, -1, false
			}
		}
		return vulnColumn{}, -1, false
	}

	res := &ParseResult{}
	for _, row := range sheet.Rows[1:] {
		get := func(key string) (vulnColumn, string) {
			col, i, _ := at(key)
			if i < 0 || i >= len(row.Cells) {
				return col, ""
			}
			return col, strings.TrimSpace(row.Cells[i])
		}

		// fail 收集行级错误并终止当前行。收集上限 maxRowErrors：
		// 错误行多到失去阅读意义时停止追加（不是停止解析——
		// 统计「还有多少错」对用户没有行动价值，重要的是能看到前 200 条）。
		fail := func(col vulnColumn, value, msg string) {
			if len(res.Errors) < maxRowErrors {
				res.Errors = append(res.Errors, RowError{
					Row: row.Number, Column: col.Header,
					Value: truncateRunes(value, 60), Message: msg,
				})
			}
		}

		titleCol, title := get("title")
		if title == "" {
			fail(titleCol, title, "漏洞名称不能为空")
			continue
		}
		if r := []rune(title); len(r) > 255 {
			fail(titleCol, title, "漏洞名称最多 255 字")
			continue
		}

		v := ParsedVuln{Title: title}

		if _, cve := get("cve"); cve != "" {
			if r := []rune(cve); len(r) > 512 {
				fail(vulnCol("cve"), cve, "CVE 编号最多 512 字符")
				continue
			}
			v.CVEIDs = cleanCVEs(strings.Split(cve, ","))
		}

		_, sevRaw := get("severity")
		if sevRaw == "" {
			v.Severity = SeverityDefaultNessus
		} else if sev, ok := severityFromWord(sevRaw); ok {
			v.Severity = sev
		} else if score, err := strconv.ParseFloat(sevRaw, 64); err == nil && score >= 0 && score <= 10 {
			// 数字：1–5 当等级，其余当 CVSS 分值。
			if score >= 1 && score <= 5 && !strings.Contains(sevRaw, ".") {
				v.Severity = uint8(score)
			} else {
				v.Severity = severityFromCVSS(score)
			}
		} else {
			fail(vulnCol("severity"), sevRaw, "无法识别的严重程度，可填 严重/高/中/低/信息、Critical/High/Medium/Low/Info、1–5 或 CVSS 分值")
			continue
		}

		_, hostIP := get("host_ip")
		if hostIP != "" {
			if r := []rune(hostIP); len(r) > 64 {
				fail(vulnCol("host_ip"), hostIP, "主机 IP 最多 64 字符")
				continue
			}
			v.HostIP = hostIP
		}

		if _, portRaw := get("port"); portRaw != "" {
			p, err := strconv.ParseUint(portRaw, 10, 16)
			if err != nil || p == 0 {
				fail(vulnCol("port"), portRaw, "端口须为 1–65535 的整数，留空表示与端口无关")
				continue
			}
			pp := uint16(p)
			v.Port = &pp
		}

		if _, proto := get("protocol"); proto != "" {
			p := strings.ToLower(proto)
			if p != "tcp" && p != "udp" {
				fail(vulnCol("protocol"), proto, "协议只能填 tcp / udp 或留空")
				continue
			}
			v.Protocol = p
		}

		if _, svc := get("service"); svc != "" {
			v.Service = svc
		}
		if _, desc := get("description"); desc != "" {
			v.Description = desc
		}
		if _, sol := get("solution"); sol != "" {
			v.Solution = sol
		}

		res.Vulns = append(res.Vulns, v)
	}
	return res, nil
}

// vulnCol 按内部 key 取列定义。key 全部来自本文件内的字面量，
// 找不到时返回零值列（Header 为空串），fail 会把空列名渲染成「整行」。
func vulnCol(key string) vulnColumn {
	for _, col := range vulnColumns {
		if col.Key == key {
			return col
		}
	}
	return vulnColumn{}
}

// maxRowErrors 行级错误的收集上限。与资产导入保持同一量级。
const maxRowErrors = 200

// ExcelTemplate 生成漏洞导入模板（xlsx）。
//
// 与资产模板同构：第一张表只有表头，第二张表是逐列说明。
func ExcelTemplate() ([]byte, error) {
	headers := make([]string, 0, len(vulnColumns))
	widths := make([]float64, 0, len(vulnColumns))
	guide := make([][]string, 0, len(vulnColumns)+2)

	guide = append(guide, []string{"列名", "是否必填", "填写说明", "示例"})
	for _, col := range vulnColumns {
		headers = append(headers, col.Header)
		widths = append(widths, col.Width)
		required := "否"
		if col.Required {
			required = "是"
		}
		guide = append(guide, []string{col.Header, required, col.Note, sampleFor(col.Key)})
	}

	return spreadsheet.WriteXLSX([]spreadsheet.SheetSpec{
		{
			Name:   "漏洞清单",
			Header: headers,
			Rows:   [][]string{},
			// IP 与 CVE 强制文本：Excel 会把 192.168.001.1 改写成数字、
			// 把 CVE-2024-1 认成日期，文本格式从源头避免这种静默破坏。
			// 列字母：B=CVE编号、D=主机IP。
			TextColumns: []string{"B", "D"},
			Widths:      widths,
		},
		{
			Name:   "填写说明",
			Header: []string{"列名", "是否必填", "填写说明", "示例"},
			Rows:   guide,
			Widths: []float64{16, 10, 56, 26},
		},
	})
}

// sampleFor 各列的示例值。
func sampleFor(key string) string {
	switch key {
	case "title":
		return "TLS 版本 1.1 协议启用"
	case "cve":
		return "CVE-2011-3389"
	case "severity":
		return "中"
	case "host_ip":
		return "192.168.1.10"
	case "port":
		return "443"
	case "protocol":
		return "tcp"
	case "service":
		return "https"
	case "description":
		return "目标服务启用了已不安全的 TLS 1.1 协议"
	case "solution":
		return "禁用 TLS 1.1，仅启用 TLS 1.2 及以上版本"
	}
	return ""
}
