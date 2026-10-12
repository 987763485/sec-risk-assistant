package reportparser

import (
	"os"
	"testing"

	"secrisk/server/internal/model"
)

// 三个格式的样本文件是本包的回归基石：真实扫描器导出的结构里
// 总有文档里不写的杂质（CDATA、属性缺失、奇怪的端口写法），
// 样本锁住这些事实，改动解析器时才会知道哪些行为是被依赖的。

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("读取样本 %s 失败: %v", name, err)
	}
	return data
}

func TestParseNessusSample(t *testing.T) {
	data := mustRead(t, "sample.nessus")

	if f := DetectFormat(data); f != model.ScanFormatNessus {
		t.Fatalf("DetectFormat = %q，期望 nessus", f)
	}
	res, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Format != model.ScanFormatNessus {
		t.Errorf("res.Format = %q", res.Format)
	}
	if len(res.Vulns) != 4 {
		t.Fatalf("漏洞条数 = %d，期望 4", len(res.Vulns))
	}

	// 第一条：cvss_base_score(3.7) 优先于 severity 属性(2/MEDIUM)，
	// 3.7 → 低档 → 2。CVSS 是客观数值，risk_factor 是它的派生品。
	v := res.Vulns[0]
	if v.Title != "SSL Medium Strength Cipher Suites Supported (SWEET32)" {
		t.Errorf("第一条标题不符: %q", v.Title)
	}
	if v.HostIP != "192.168.1.10" {
		t.Errorf("第一条 host = %q，应取自 HostProperties 的 HOST tag 而不是 name 属性(UUID)", v.HostIP)
	}
	if v.Severity != 2 || v.SeverityRaw != "3.7" {
		t.Errorf("第一条等级 = %d/%q，CVSS 3.7 应映射 2", v.Severity, v.SeverityRaw)
	}
	if v.Port == nil || *v.Port != 443 {
		t.Errorf("第一条端口 = %v，期望 443", v.Port)
	}
	if v.Protocol != "tcp" || v.Service != "https" {
		t.Errorf("第一条协议/服务 = %q/%q", v.Protocol, v.Service)
	}
	// CVE 大写化 + 去重 + 保留两个
	if len(v.CVEIDs) != 2 || v.CVEIDs[0] != "CVE-2016-2183" || v.CVEIDs[1] != "CVE-2016-6329" {
		t.Errorf("第一条 CVE = %v", v.CVEIDs)
	}

	// 第二条：cvss_base_score 优先于 risk_factor（8.1 → 4 High）
	v2 := res.Vulns[1]
	if v2.Severity != 4 || v2.SeverityRaw != "8.1" {
		t.Errorf("第二条等级 = %d/%q，CVSS 8.1 应映射 4", v2.Severity, v2.SeverityRaw)
	}
	if v2.Description == "" || v2.Solution == "" {
		t.Error("第二条描述/建议不应为空（CDATA 内容应被取出）")
	}

	// 第三条：severity=4 CRITICAL 但无 CVSS → 5
	if v3 := res.Vulns[2]; v3.Severity != 5 || v3.SeverityRaw != "Critical" {
		t.Errorf("第三条等级 = %d/%q", v3.Severity, v3.SeverityRaw)
	}
	// port="0" + svc_name="general" 应视为与端口无关
	if v3 := res.Vulns[2]; v3.Port != nil || v3.Service != "" {
		t.Errorf("第三条端口/服务 = %v/%q，port=0 与 general 应清空", v3.Port, v3.Service)
	}

	// 第二台主机的 INFO 条目 → 1
	if v4 := res.Vulns[3]; v4.Severity != 1 || v4.HostIP != "10.0.0.5" {
		t.Errorf("第四条 = %d/%q", v4.Severity, v4.HostIP)
	}
}

func TestParseOpenVASSample(t *testing.T) {
	data := mustRead(t, "sample_openvas.xml")

	if f := DetectFormat(data); f != model.ScanFormatOpenVAS {
		t.Fatalf("DetectFormat = %q，期望 openvas", f)
	}
	res, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Vulns) != 3 {
		t.Fatalf("漏洞条数 = %d，期望 3", len(res.Vulns))
	}

	v := res.Vulns[0]
	if v.Title != "TLS Version 1.1 Protocol Detection" {
		t.Errorf("第一条标题 = %q", v.Title)
	}
	if v.HostIP != "192.168.1.10" {
		t.Errorf("第一条 host = %q", v.HostIP)
	}
	if v.Severity != 3 || v.SeverityRaw != "4.3" {
		t.Errorf("第一条等级 = %d/%q，CVSS 4.3 应映射 3", v.Severity, v.SeverityRaw)
	}
	if v.Port == nil || *v.Port != 443 || v.Protocol != "tcp" {
		t.Errorf("第一条端口 = %v/%q，'443/tcp' 应拆出端口与协议", v.Port, v.Protocol)
	}
	if len(v.CVEIDs) != 1 || v.CVEIDs[0] != "CVE-2011-3389" {
		t.Errorf("第一条 CVE = %v", v.CVEIDs)
	}

	// 第二条：9.8 → 5；port 5432
	v2 := res.Vulns[1]
	if v2.Severity != 5 {
		t.Errorf("第二条等级 = %d，CVSS 9.8 应映射 5", v2.Severity)
	}
	if v2.Port == nil || *v2.Port != 5432 {
		t.Errorf("第二条端口 = %v", v2.Port)
	}

	// 第三条：severity -1.0（QOD 不可判）→ 按信息级处理，不报错
	v3 := res.Vulns[2]
	if v3.Severity != 1 {
		t.Errorf("第三条等级 = %d，-1.0 应按信息级处理", v3.Severity)
	}
	// general/tcp → 与端口无关
	if v3.Port != nil {
		t.Errorf("第三条端口 = %v，general/tcp 应视为与端口无关", v3.Port)
	}
}

func TestParseCSVSample(t *testing.T) {
	data := mustRead(t, "sample_vulns.csv")

	if f := DetectFormat(data); f != model.ScanFormatExcel {
		t.Fatalf("DetectFormat = %q，期望 excel", f)
	}
	res, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Vulns) != 3 {
		t.Fatalf("漏洞条数 = %d，期望 3", len(res.Vulns))
	}
	v := res.Vulns[0]
	if v.Title != "弱口令登录" || v.HostIP != "192.168.1.20" || v.Severity != 4 {
		t.Errorf("第一条 = %q %q %d", v.Title, v.HostIP, v.Severity)
	}
	if len(v.CVEIDs) != 1 || v.CVEIDs[0] != "CVE-1999-0502" {
		t.Errorf("第一条 CVE = %v", v.CVEIDs)
	}
	// 第二条 CVE 为空、severity=中 → 3
	if v2 := res.Vulns[1]; v2.Severity != 3 || len(v2.CVEIDs) != 0 {
		t.Errorf("第二条 = %d %v", v2.Severity, v2.CVEIDs)
	}
	// 第三条 severity=低 → 2
	if v3 := res.Vulns[2]; v3.Severity != 2 {
		t.Errorf("第三条等级 = %d", v3.Severity)
	}
}

func TestExcelMissingRequiredColumn(t *testing.T) {
	csv := "CVE编号,严重程度\nCVE-2024-1234,高\n"
	res, err := Parse([]byte(csv))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.MissingColumns) != 1 || res.MissingColumns[0] != "漏洞名称" {
		t.Fatalf("MissingColumns = %v，期望 [漏洞名称]", res.MissingColumns)
	}
}

func TestExcelRowErrorsWithLineNumber(t *testing.T) {
	// 表头 1 行 + 数据 3 行；第 3、4 行有错
	csv := "漏洞名称,主机IP,端口\n正常漏洞,10.0.0.1,80\n,10.0.0.2,80\n名称,10.0.0.3,99999\n"
	res, err := Parse([]byte(csv))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Vulns) != 1 {
		t.Fatalf("合法条数 = %d，期望 1", len(res.Vulns))
	}
	if len(res.Errors) != 2 {
		t.Fatalf("错误条数 = %d，期望 2", len(res.Errors))
	}
	// 源文件行号：表头占第 1 行，错误分别在第 3、4 行
	if res.Errors[0].Row != 3 || res.Errors[0].Column != "漏洞名称" {
		t.Errorf("第一条错误 = 行%d 列%q", res.Errors[0].Row, res.Errors[0].Column)
	}
	if res.Errors[1].Row != 4 || res.Errors[1].Column != "端口" {
		t.Errorf("第二条错误 = 行%d 列%q", res.Errors[1].Row, res.Errors[1].Column)
	}
}

func TestExcelOnlyHeaderIsNoVulns(t *testing.T) {
	// P2 资产导入在这里踩过坑：只有表头时必须报「没有条目」，
	// 而不是空着成功。漏洞导入沿用同一判据。
	csv := "漏洞名称,CVE编号,严重程度\n"
	if _, err := Parse([]byte(csv)); err != ErrNoVulns {
		t.Fatalf("期望 ErrNoVulns，got %v", err)
	}
}

func TestUnknownFormat(t *testing.T) {
	// JSON 不是 XML 也不是表格魔数，会落到 CSV 路径；列头对不上时
	// 应得到「缺少必需列」而不是逐行报「名称为空」——前者告诉用户
	// 「换个正确格式的文件」，后者只会让人莫名其妙。
	data := []byte(`{"this": "is json"}`)
	res, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.MissingColumns) == 0 {
		t.Fatalf("JSON 内容应产生「缺少必需列」，got %v", res.MissingColumns)
	}
}

func TestEmptyInput(t *testing.T) {
	if _, err := Parse([]byte("   ")); err != ErrNoVulns {
		t.Fatalf("空输入期望 ErrNoVulns，got %v", err)
	}
}

func TestBrokenXMLIsMalformed(t *testing.T) {
	// 根元素是 Nessus 的嗅探目标但内容损坏：应当报 ErrMalformed，
	// 绝不能被转交给 Excel 解析器（那会产生荒谬的逐行报错）。
	data := []byte("<NessusClientData_v2><Report><ReportHost name=\"x\">")
	// 补上闭合让嗅探通过，但内部结构残缺
	data = append(data, []byte("</ReportHost></Report></NessusClientData_v2>")...)
	if f := DetectFormat(data); f != model.ScanFormatNessus {
		t.Fatalf("嗅探应识别为 nessus，got %q", f)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("残缺 XML 应报错")
	}
}

func TestSeverityFromWord(t *testing.T) {
	cases := map[string]uint8{
		"Critical": 5, "严重": 5, "5": 5,
		"High": 4, "高": 4, "4": 4,
		"Medium": 3, "中": 3, "中危": 3, "3": 3,
		"Low": 2, "低": 2, "2": 2,
		"Info": 1, "信息": 1, "1": 1,
	}
	for word, want := range cases {
		got, ok := severityFromWord(word)
		if !ok || got != want {
			t.Errorf("severityFromWord(%q) = %d,%v；期望 %d", word, got, ok, want)
		}
	}
	if _, ok := severityFromWord("不知道"); ok {
		t.Error("未知词不应被识别")
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := map[float64]uint8{10: 5, 9.0: 5, 8.9: 4, 7.0: 4, 6.9: 3, 4.0: 3, 3.9: 2, 0.1: 2, 0: 1, 12: 5, -3: 1}
	for score, want := range cases {
		if got := severityFromCVSS(score); got != want {
			t.Errorf("severityFromCVSS(%v) = %d；期望 %d", score, got, want)
		}
	}
}
