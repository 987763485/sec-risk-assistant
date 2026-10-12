// Package model 的扫描文件模型定义。
//
// 可空列一律用指针的约定沿用 user.go / asset.go。
package model

import "time"

// ScanFileFormat 上传文件的判定格式。
//
// 空串表示「上传了但还没解析」（解析在两阶段流程的第二步才发生），
// 因此不要用 omitempty 把它从 JSON 里抹掉——前端需要区分
// 「未解析」和「解析失败」两种可操作状态。
type ScanFileFormat string

const (
	// ScanFormatNessus Nessus 导出的 .nessus（XML）
	ScanFormatNessus ScanFileFormat = "nessus"
	// ScanFormatOpenVAS OpenVAS/GVM 导出的 XML
	ScanFormatOpenVAS ScanFileFormat = "openvas"
	// ScanFormatExcel 通用表格（xlsx / csv）
	ScanFormatExcel ScanFileFormat = "excel"
)

// ScanParseStatus 文件的解析状态。
type ScanParseStatus string

const (
	// ScanParseUnparsed 刚上传，还没跑解析（或解析预览后尚未确认入库）。
	ScanParseUnparsed ScanParseStatus = "unparsed"
	// ScanParseParsed 漏洞已写入 vulnerabilities。
	ScanParseParsed ScanParseStatus = "parsed"
	// ScanParseFailed 解析失败。失败不锁死文件：修好格式可以重新 preview。
	ScanParseFailed ScanParseStatus = "failed"
)

// ScanFile 上传的扫描报告。
//
// SHA256 是去重判据：同一内容的文件在库里永远只有一行、在磁盘上
// 只有一份。重复上传是幂等操作，服务层直接返回已有记录。
//
// StoragePath 故意不含扩展名（见迁移 000005 头部约束 2）：
// 「文件在磁盘上叫什么」与「用户下载时叫什么」是两件事。
type ScanFile struct {
	ID uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	// SHA256 内容哈希，CHAR(64)，唯一索引。
	SHA256       string          `gorm:"column:sha256;size:64"`
	OriginalName string          `gorm:"column:original_name;size:255"`
	StoragePath  string          `gorm:"column:storage_path;size:255"`
	SizeBytes    uint64          `gorm:"column:size_bytes"`
	MimeType     string          `gorm:"column:mime_type;size:64"`
	Format       ScanFileFormat  `gorm:"column:format;size:16"`
	ParseStatus  ScanParseStatus `gorm:"column:parse_status;size:16"`
	// ParsedAt 解析入库时间。NULL 表示尚未 commit（与 ParseStatus 冗余，
	// 但给列表页一个可直接排序的时间列比让前端拼状态有用）。
	ParsedAt   *time.Time `gorm:"column:parsed_at"`
	VulnCount  uint32     `gorm:"column:vuln_count"`
	UploadedBy *uint64    `gorm:"column:uploaded_by"`
	CreatedAt  time.Time  `gorm:"column:created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (ScanFile) TableName() string { return "scan_files" }
