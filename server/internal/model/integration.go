// Package model 的扩展模块模型定义（P7）。
package model

import "time"

// Integration 三方情报源的接入配置。
//
// 表里同时承载**配置**（name / type / base_url / credential_env / enabled /
// timeout_ms）与**最近一次运行态**（last_* 四列）。两者同表是刻意的：
// P7 不做拉取历史（见迁移 000008 约束 4），运行态只有一行，拆表会让
// 列表页为了一行数据去 JOIN。
//
// ⚠️ 因此 UpdatedAt 的语义是「行最后变更时间」，**包含运行态写入**
// （迁移 000008 约束 5）。界面不得把它呈现为「配置最后修改时间」。
type Integration struct {
	ID   uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	Name string `gorm:"column:name;size:64"`
	// Type 适配器类型，取值域来自 pkg/intelfeed 的 `Type*` 常量。
	//
	// 刻意写成 string 而不在 model 里再定义一遍类型常量：
	// 适配器类型与它的元信息（是否需要凭据、默认地址）都属于 intelfeed，
	// 这里再列一份就等于有两个地方回答「支持哪些源」，
	// 而两份定义的分叉不会报错，只会在某次比较里静默不相等。
	Type string `gorm:"column:type;size:32"`
	// BaseURL 用户可控的出站目标。写入前必经 SSRF 校验
	// （pkg/intelfeed.CheckEndpoint），校验失败的请求根本走不到仓储层。
	BaseURL string `gorm:"column:base_url;size:255"`
	// CredentialEnv 凭据所在的**环境变量名**（不是凭据本身）。
	// 空串表示该集成无需凭据。表里永远不出现凭据明文（迁移 000008 约束 2）。
	CredentialEnv string `gorm:"column:credential_env;size:64"`
	Enabled       bool   `gorm:"column:enabled"`
	// TimeoutMS 单次拉取超时（毫秒）。上下限由 intelfeed 的
	// MinTimeout / MaxTimeout 决定，服务层在写库前收敛。
	TimeoutMS int `gorm:"column:timeout_ms"`

	// —— 运行态：只保留最近一次 ——
	LastRunAt     *time.Time `gorm:"column:last_run_at"`
	LastStatus    string     `gorm:"column:last_status;size:16"`
	LastError     string     `gorm:"column:last_error;size:255"`
	LastLatencyMS *int       `gorm:"column:last_latency_ms"`

	CreatedBy *uint64   `gorm:"column:created_by"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (Integration) TableName() string { return "integrations" }

// 集成运行态取值。空串表示「从未拉取过」，因此不进这个列表。
const (
	// IntegrationRunSuccess 最近一次拉取成功
	IntegrationRunSuccess = "success"
	// IntegrationRunFailed 最近一次拉取失败
	IntegrationRunFailed = "failed"
)

// HasRun 判断该集成是否拉取过。
//
// 判据是 LastStatus 非空而不是 LastRunAt 非空：两者本应同步写入，
// 但 status 是字符串、有明确的「空串 = 未拉取」语义，而时间列一旦
// 被某次迁移或人工操作写脏，非空就再也退不回 NULL。
func (i *Integration) HasRun() bool { return i.LastStatus != "" }

// VulnIntel 漏洞情报快照。
//
// 它是**派生数据**：删掉漏洞时随之 CASCADE 清理（迁移 000008 约束 7），
// 与整改单那套「业务事实永不被上游改写」的立场相反——
// 判据是「谁没了之后，这条记录还有没有独立意义」。
type VulnIntel struct {
	ID     uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	VulnID uint64 `gorm:"column:vuln_id"`
	// Source 情报源标识，取值域来自 pkg/intelfeed 的 `Type*` 常量。
	//
	// 存**适配器类型**而不是 integrations.id：类型是适配器的不变量，
	// 而集成配置可以被删除重建。若存 id，删掉配置会让历史情报变成
	// 指向一个不存在的配置的行（同 000007 约束 1 的教训：
	// 下游业务身份不能建在会被删除重建的表上）。
	Source string `gorm:"column:source;size:32"`
	// CVEID 本条情报对应的 CVE 编号；无 CVE 的漏洞为空串。
	// ⚠️ 它是唯一键 (vuln_id, source, cve_id) 的一部分：
	// 一条漏洞可挂多个 CVE，唯一键少一列会让后一条覆盖前一条（迁移 000008 约束 6）。
	CVEID       string  `gorm:"column:cve_id;size:64"`
	Title       string  `gorm:"column:title;size:255"`
	Description *string `gorm:"column:description;type:text"`
	// Severity 归一化后的严重度，取值域来自 pkg/intelfeed 的 `Severity*` 常量，
	// 入库时定稿、之后不再重算（快照的本分，见 intelfeed 包注释）。
	Severity    string     `gorm:"column:severity;size:16"`
	CVSSScore   *float64   `gorm:"column:cvss_score"`
	CVSSVector  string     `gorm:"column:cvss_vector;size:128"`
	PublishedAt *time.Time `gorm:"column:published_at"`
	// ReferencesJSON / RawJSON 用 *string 而不是 json.RawMessage：
	// 空值必须是 SQL NULL，而不是会被 MySQL 拒绝的非法 JSON 空串
	// （同 AuditLog.Detail 的理由）。
	ReferencesJSON *string `gorm:"column:references_json;type:json"`
	RawJSON        *string `gorm:"column:raw_json;type:json"`
	// FetchedAt 本次抓取时间，**不等于** PublishedAt（上游的发布时间）。
	// 两个时间都要留：前者回答「我们什么时候知道的」，
	// 后者回答「这个漏洞什么时候公开的」，混用会让「情报是否过期」
	// 这类判断做出错误结论。
	FetchedAt time.Time `gorm:"column:fetched_at"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (VulnIntel) TableName() string { return "vuln_intel" }
