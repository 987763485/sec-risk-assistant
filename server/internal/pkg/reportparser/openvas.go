package reportparser

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"secrisk/server/internal/model"
)

// OpenVASParser 解析 OpenVAS / GVM 导出的 XML 报告。
//
// 真实样例的关键结构（GVM 20.08+ 的 full_report 格式）：
//
//	<report extension="xml" format="xml" content_type="full_report">
//	  <envelope>…</envelope>
//	  <host>
//	    <ip>10.0.0.1</ip>
//	    <hostname>web01</hostname>
//	  </host>
//	  <results start="1" max="100">
//	    <result id="1">
//	      <host>10.0.0.1</host>
//	      <port>443/tcp</port>
//	      <name>TLS Version 1.1 Protocol Detection</name>
//	      <severity>4.3</severity>            ← 顶层 CVSS 分值
//	      <description>…</description>
//	      <solution type="…">…</solution>
//	      <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
//	        <cve>CVE-2011-3389</cve>          ← 0..n 个
//	      </nvt>
//	    </result>
//	  </results>
//	</report>
//
// 旧版（GSA 9 / OpenVAS 9）把结果放在 <report><results> 的同级结构里，
// 元素名一致，只是外层多了 <report id> 与 <name>——本结构的声明对两种
// 版本都能取到 <results>，不需要为旧版单独写解析器。
type OpenVASParser struct{}

// Format 实现接口。
func (OpenVASParser) Format() model.ScanFileFormat { return model.ScanFormatOpenVAS }

// openvasRoot 嗅探根元素。
type openvasRoot struct {
	XMLName xml.Name `xml:"report"`
}

// Detect 实现接口：根元素是 report 即认领。
//
// 注意「report」这个根元素名很通用——Detect 放在这里是**排他顺序**上
// 的第二位，Nessus 先认领自己的根元素；若未来引入其他以 report 为根的
// 格式，需要把识别条件收紧到 format="xml" 属性或 <envelope> 子元素。
func (OpenVASParser) Detect(data []byte) bool {
	var root openvasRoot
	return xml.Unmarshal(data, &root) == nil && root.XMLName.Local == "report"
}

type openvasReport struct {
	Results []openvasResult `xml:"results>result"`
}

type openvasResult struct {
	Host        string `xml:"host"`
	Port        string `xml:"port"`
	Name        string `xml:"name"`
	Severity    string `xml:"severity"`
	Description string `xml:"description"`
	// Solution 带可选的 type 属性，取 chardata 即可。
	Solution string `xml:"solution"`
	NVT      struct {
		OID string   `xml:"oid,attr"`
		CVE []string `xml:"cve"`
	} `xml:"nvt"`
}

// Parse 实现接口。
func (OpenVASParser) Parse(data []byte) (*ParseResult, error) {
	var report openvasReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformed, err)
	}

	var vulns []ParsedVuln
	for _, r := range report.Results {
		title := strings.TrimSpace(r.Name)
		if title == "" {
			// NVT oid 是 OpenVAS 里唯一稳定的标识，名字缺失时用它兜底。
			title = "未命名条目 #" + strings.TrimSpace(r.NVT.OID)
		}

		severity, raw := openvasSeverity(r.Severity)
		port, proto := splitPortSpec(r.Port)

		hostIP := strings.TrimSpace(r.Host)
		// OpenVAS 的 host 元素偶尔是 "10.0.0.1 (web01)" 的形式——
		// 括号里的别名拆出来存 Hostname，IP 部分保留做关联判据。
		hostName := ""
		if idx := strings.IndexByte(hostIP, '('); idx > 0 && strings.HasSuffix(hostIP, ")") {
			hostName = strings.TrimSpace(hostIP[idx+1 : len(hostIP)-1])
			hostIP = strings.TrimSpace(hostIP[:idx])
		}

		vulns = append(vulns, ParsedVuln{
			Title:       truncateRunes(title, 255),
			CVEIDs:      cleanCVEs(r.NVT.CVE),
			SeverityRaw: raw,
			Severity:    severity,
			Description: strings.TrimSpace(r.Description),
			Solution:    strings.TrimSpace(r.Solution),
			HostIP:      hostIP,
			Hostname:    hostName,
			Port:        port,
			Protocol:    proto,
		})
		if len(vulns) > MaxVulns {
			return nil, fmt.Errorf("%w: 超过 %d 条", ErrTooManyVulns, MaxVulns)
		}
	}
	return &ParseResult{Vulns: vulns}, nil
}

// openvasSeverity 计算 1–5 等级与原始串。
//
// severity 元素是 CVSS 浮点；个别旧版写 "-1.0" 表示 QOD 不可判——
// 负值按「信息级」处理而不是报错，一条解析不了等级的结果不值得
// 让整份报告失败。
func openvasSeverity(raw string) (uint8, string) {
	raw = strings.TrimSpace(raw)
	if score, err := strconv.ParseFloat(raw, 64); err == nil {
		if score < 0 {
			return 1, raw
		}
		return severityFromCVSS(score), raw
	}
	// 非数字时尝试按等级词识别（部分导出器输出 "High"）。
	if sev, ok := severityFromWord(raw); ok {
		return sev, raw
	}
	return SeverityDefaultNessus, raw
}
