package reportparser

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"secrisk/server/internal/model"
)

// NessusParser 解析 Nessus 导出的 .nessus 报告（XML）。
//
// 真实样例的关键结构（Tenable 官方文档 Nexpose/Nessus v2 XML）：
//
//	<NessusClientData_v2>
//	  <Report name="...">
//	    <ReportHost name="10.0.0.1">
//	      <HostProperties>
//	        <tag name="HOST">10.0.0.1</tag>
//	        <tag name="NAME">web01</tag>       ← 可选，主机别名
//	      </HostProperties>
//	      <ReportItem port="443" svc_name="https" protocol="tcp"
//	                  severity="2" pluginID="42873" pluginName="SSL Medium Strength...">
//	        <description>…</description>
//	        <solution>…</solution>
//	        <cve>CVE-2011-3389</cve>           ← 0..n 个
//	        <risk_factor>MEDIUM</risk_factor>
//	      </ReportItem>
//	    </ReportHost>
//	  </Report>
//	</NessusClientData_v2>
type NessusParser struct{}

// Format 实现接口。
func (NessusParser) Format() model.ScanFileFormat { return model.ScanFormatNessus }

// nessusRoot 只取根元素名做嗅探，不展开整棵树。
type nessusRoot struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
}

// Detect 实现接口：根元素是 NessusClientData_v2 即认领。
func (NessusParser) Detect(data []byte) bool {
	var root nessusRoot
	return xml.Unmarshal(data, &root) == nil && root.XMLName.Local == "NessusClientData_v2"
}

// nessusReport 解析所需的子树。Go 的 encoding/xml 是「声明了什么取什么」，
// 未声明的元素自动跳过，因此只需要声明关心的字段。
type nessusReport struct {
	Hosts []nessusHost `xml:"Report>ReportHost"`
}

type nessusHost struct {
	Name       string          `xml:"name,attr"`
	Properties []nessusHostTag `xml:"HostProperties>tag"`
	Items      []nessusItem    `xml:"ReportItem"`
}

type nessusHostTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusItem struct {
	Port       string `xml:"port,attr"`
	Protocol   string `xml:"protocol,attr"`
	SvcName    string `xml:"svc_name,attr"`
	Severity   string `xml:"severity,attr"`
	PluginName string `xml:"pluginName,attr"`
	PluginID   string `xml:"pluginID,attr"`
	FName      string `xml:"fname,attr"`
	// CVE 与 risk_factor 是 chardata 元素；同一 ReportItem 可有多个 <cve>。
	CVEs       []string `xml:"cve"`
	RiskFactor string   `xml:"risk_factor"`
	CVSSScore  string   `xml:"cvss_base_score"` // 部分插件提供，优先于 risk_factor
	CVSSVector string   `xml:"cvss_vector"`
	// Description / Solution 在真实报告里可能带 CDATA，
	// chardata 声明对两者都成立（CDATA 内容按 chardata 交付）。
	Description string `xml:"description"`
	Solution    string `xml:"solution"`
}

// Parse 实现接口。
func (NessusParser) Parse(data []byte) (*ParseResult, error) {
	var report nessusReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformed, err)
	}

	var vulns []ParsedVuln
	for _, host := range report.Hosts {
		// HostProperties 里的 HOST tag 才是规范 IP 来源；name 属性在
		// 部分 Nessus 版本里是 UUID 而不是 IP，直接信它会把关联挂歪。
		hostIP := ""
		hostName := host.Name
		for _, tag := range host.Properties {
			switch strings.ToUpper(tag.Name) {
			case "HOST":
				hostIP = strings.TrimSpace(tag.Value)
			case "NAME":
				if v := strings.TrimSpace(tag.Value); v != "" {
					hostName = v
				}
			}
		}

		for _, item := range host.Items {
			title := strings.TrimSpace(item.PluginName)
			if title == "" {
				title = strings.TrimSpace(item.FName)
			}
			if title == "" {
				// 没有名字的条目对用户没有意义（列表里显示为空行），
				// 用 pluginID 兜底保证可辨识。
				title = "未命名条目 #" + strings.TrimSpace(item.PluginID)
			}

			severity, raw := nessusSeverity(item)

			port, protocol := parseNessusPort(item.Port)
			if protocol == "" {
				protocol = strings.ToLower(strings.TrimSpace(item.Protocol))
			}
			service := strings.TrimSpace(item.SvcName)
			if service == "general" {
				// Nessus 用 general 表示「与具体端口无关」，
				// 写进 service 列只会制造噪音。
				service = ""
			}

			vulns = append(vulns, ParsedVuln{
				Title:       truncateRunes(title, 255),
				CVEIDs:      cleanCVEs(item.CVEs),
				SeverityRaw: raw,
				Severity:    severity,
				Description: strings.TrimSpace(item.Description),
				Solution:    strings.TrimSpace(item.Solution),
				HostIP:      hostIP,
				Hostname:    hostName,
				Port:        port,
				Protocol:    protocol,
				Service:     service,
			})
			if len(vulns) > MaxVulns {
				return nil, fmt.Errorf("%w: 超过 %d 条", ErrTooManyVulns, MaxVulns)
			}
		}
	}
	return &ParseResult{Vulns: vulns}, nil
}

// nessusSeverity 计算 1–5 的等级与原始串。
//
// 优先 cvss_base_score（0–10 浮点），其次 severity 属性
// （Nessus 的 0–4 档：info/low/medium/high/critical）。
// 两个都缺失或非法时落到默认值 3——「看不懂」不该变成「当成最低」。
func nessusSeverity(item nessusItem) (uint8, string) {
	if item.CVSSScore != "" {
		if score, err := strconv.ParseFloat(strings.TrimSpace(item.CVSSScore), 64); err == nil {
			return severityFromCVSS(score), strings.TrimSpace(item.CVSSScore)
		}
	}
	switch strings.ToLower(strings.TrimSpace(item.Severity)) {
	case "0", "info", "informational":
		return 1, "Informational"
	case "1", "low":
		return 2, "Low"
	case "2", "medium":
		return 3, "Medium"
	case "3", "high":
		return 4, "High"
	case "4", "critical":
		return 5, "Critical"
	}
	return SeverityDefaultNessus, ""
}

// SeverityDefaultNessus 等级信息缺失时的默认值。
const SeverityDefaultNessus = 3

// parseNessusPort 解析 port 属性。真实报告里有 "443"、"443,80"（少见）、
// "0"（表示与端口无关）三种形态。
func parseNessusPort(spec string) (*uint16, string) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "0" {
		return nil, ""
	}
	// "443,80" 取第一个端口；取不到（非数字）就整体视为与端口无关。
	first := strings.SplitN(spec, ",", 2)[0]
	n, err := strconv.ParseUint(strings.TrimSpace(first), 10, 16)
	if err != nil || n == 0 {
		return nil, ""
	}
	p := uint16(n)
	return &p, ""
}

// cleanCVEs 去重、去空、规范成大写 CVE-YYYY-NNNN 形式。
func cleanCVEs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" || !strings.HasPrefix(s, "CVE-") {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// truncateRunes 按 rune 截断到上限。title 列只有 255 字符，
// Nessus 的 pluginName 一般远短于此，这只是防御性兜底。
func truncateRunes(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}
