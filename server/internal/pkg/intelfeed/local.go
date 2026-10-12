package intelfeed

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// localFeed 离线驱动：不访问网络，按内置数据返回。
//
// ▍它为什么必须存在
//
// 不是为了让测试「好写」。它解决的是一个具体问题：**验收标志不能依赖外网**。
//
// P7 的验收标志是「配置后能拉取一条 CVE 信息」。如果这句话只能靠连 NVD
// 来证明，那么 CI 断网、NVD 限流、API Key 过期这三种情况都会让守门失败——
// 而它们**与本次改动毫无关系**。守门脚本一旦开始随机变红，人就会开始
// 习惯性重跑，于是真正的红灯也被忽略。这正是「失效的守门比没有守门更糟」
// 的机制。
//
// 因此本驱动把「拉取这条链路是通的」（配置 → 权限 → SSRF 校验 →
// 适配器 → 落快照 → 写运行态 → 审计）与外网可达性彻底解耦：
// local 驱动让前者可以**确定性地**被验证，nvd 适配器则负责证明后者。
//
// ⚠️ 它不绕过任何一层：SSRF 校验、超时收敛、唯一键、审计照常生效。
// 唯一的差别是「不发出网络请求」——所以它才能被用作全链路断言的载体。
type localFeed struct{}

// Type 实现 Feed。
func (localFeed) Type() string { return TypeLocal }

// localRecord 内置数据集里的一条记录。
type localRecord struct {
	Title       string
	Description string
	Severity    string
	CVSSScore   float64
	CVSSVector  string
	Published   string
	References  []string
}

// localDataset 内置情报数据。
//
// 刻意选真实存在的 CVE 而不是「CVE-0000-0001」这类占位符：
// 守门脚本的断言里会出现严重度、分数与描述片段，用真实数据可以让
// 断言写得更具体（`CVE-2021-44228 的 CVSS 必须是 10.0`），
// 而占位符会让断言退化成「只要不是空就行」。
var localDataset = map[string]localRecord{
	"CVE-2021-44228": {
		Title: "Apache Log4j2 远程代码执行漏洞（Log4Shell）",
		Description: "Apache Log4j2 在处理日志消息时会对 `${jndi:...}` 形式的字符串做 " +
			"JNDI 查找，攻击者可通过构造恶意日志内容触发远程类加载，进而在目标进程内执行任意代码。" +
			"该漏洞无需认证即可利用，影响范围覆盖 2.0-beta9 至 2.14.1。",
		Severity:   SeverityCritical,
		CVSSScore:  10.0,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Published:  "2021-12-10T10:15:09.143",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			"https://logging.apache.org/log4j/2.x/security.html",
		},
	},
	"CVE-2017-5638": {
		Title: "Apache Struts 2 远程代码执行漏洞（S2-045）",
		Description: "Apache Struts 2 的 Jakarta Multipart 解析器在处理 Content-Type 头时，" +
			"对异常信息处理不当，攻击者可构造包含 OGNL 表达式的 Content-Type 头实现远程代码执行。",
		Severity:   SeverityCritical,
		CVSSScore:  10.0,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Published:  "2017-03-10T22:59:00.000",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
		},
	},
	"CVE-2018-15473": {
		Title: "OpenSSH 用户名枚举漏洞",
		Description: "OpenSSH 8.7 之前的版本在认证过程中对不存在的用户名与密码错误的响应" +
			"存在可测量的时间差与报文差异，远程攻击者据此可枚举出系统上的有效用户名。",
		Severity:   SeverityMedium,
		CVSSScore:  5.3,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Published:  "2018-08-17T18:29:00.000",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
		},
	},
}

// Fetch 实现 Feed。
func (localFeed) Fetch(_ context.Context, req Request) (*Record, error) {
	cveID := strings.ToUpper(strings.TrimSpace(req.CVEID))
	if cveID == "" {
		return nil, ErrNotFound
	}

	row, ok := localDataset[cveID]
	if !ok {
		// 与真实适配器的语义保持一致：明确回答「没有这条」，
		// 而不是回一个空记录让上层以为是拉取成功但内容为空。
		return nil, ErrNotFound
	}

	score := row.CVSSScore
	rec := &Record{
		CVEID:       cveID,
		Title:       row.Title,
		Description: row.Description,
		Severity:    NormalizeSeverity(row.Severity, &score),
		CVSSScore:   &score,
		CVSSVector:  row.CVSSVector,
		Published:   parseNVDTime(row.Published),
		// 每次返回新切片：直接把 map 里的切片交出去，调用方一旦原地改动
		// 就会污染全局数据，而这类污染在下一次拉取时才显形。
		References: append([]string(nil), row.References...),
	}

	// Raw 的形态与 NVD 适配器保持一致（同一套字段名），
	// 这样「界面显示的与 raw_json 一致」这条断言对两种源都成立。
	if raw, err := json.Marshal(map[string]any{
		"id":           cveID,
		"title":        row.Title,
		"description":  row.Description,
		"severity":     rec.Severity,
		"cvssScore":    row.CVSSScore,
		"cvssVector":   row.CVSSVector,
		"published":    row.Published,
		"references":   row.References,
		"source":       TypeLocal,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}); err == nil {
		rec.Raw = raw
	}

	return rec, nil
}
