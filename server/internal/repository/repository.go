// Package repository 封装数据访问。
//
// 分层边界：handler 只碰 service，service 只碰 repository，
// repository 是唯一允许出现 GORM / SQL 的层。
//
// 硬性纪律（对应安全基线第 7 条）：
//   - 过滤条件一律下推到 SQL，禁止「全表捞出后在 Go 里筛」
//   - 只用参数占位符，禁止字符串拼接 SQL
//   - 需要读改一致性的操作必须放在事务里，并对关键行加锁
package repository

import (
	"context"

	"gorm.io/gorm"
)

// GroupCount 通用的一维分组统计结果（仪表盘用）。
//
// Key 是分组维度的值（资产类型码、状态码……）。用 string 而不是各自的
// 强类型：它跨越多个领域（资产状态、整合状态、评估状态），
// 而调用方拿到它之后要做的第一件事就是映射成展示名，类型信息在那里
// 才重新变得有意义。
type GroupCount struct {
	Key   string `gorm:"column:k"`
	Count int64  `gorm:"column:cnt"`
}

// Repository 聚合全部仓储，便于依赖注入时只传一个对象。
type Repository struct {
	db         *gorm.DB
	User       *UserRepository
	Role       *RoleRepository
	Session    *SessionRepository
	Audit      *AuditRepository
	Asset      *AssetRepository
	AssetGroup *AssetGroupRepository
	Dictionary *DictionaryRepository
	ScanFile   *ScanFileRepository
	Vuln       *VulnRepository
	Assessment *AssessmentRepository
	SystemCfg  *SystemConfigRepository
	// Remediation 整改单（P6）。它在依赖图上不隶属任何其他仓储：
	// 整改单是业务事实，按 (asset_id, vuln_id) 独立存在，
	// 而不是 assessments 或 risk_items 的从属数据（见迁移 000007 约束 1）。
	Remediation *RemediationRepository
	// Integration 三方情报源配置与漏洞情报快照（P7）。
	//
	// 两张表（integrations / vuln_intel）合一个仓储：它们的关系是
	// 「配置指向适配器，适配器产出快照」，而 source 列上的取值是
	// 适配器类型而非配置 ID（见迁移 000008 约束 1）——
	// 拆成两个仓储只会让「拉取」这个动作横跨两个对象，
	// 而它们必然在同一次调用里成对出现。
	Integration *IntegrationRepository
}

// New 构建仓储聚合。
func New(db *gorm.DB) *Repository {
	return &Repository{
		db:          db,
		User:        NewUserRepository(db),
		Role:        NewRoleRepository(db),
		Session:     NewSessionRepository(db),
		Audit:       NewAuditRepository(db),
		Asset:       NewAssetRepository(db),
		AssetGroup:  NewAssetGroupRepository(db),
		Dictionary:  NewDictionaryRepository(db),
		ScanFile:    NewScanFileRepository(db),
		Vuln:        NewVulnRepository(db),
		Assessment:  NewAssessmentRepository(db),
		SystemCfg:   NewSystemConfigRepository(db),
		Remediation: NewRemediationRepository(db),
		Integration: NewIntegrationRepository(db),
	}
}

// DB 暴露底层连接，仅供 service 层开启跨仓储事务使用。
// 业务代码不应直接使用它。
func (r *Repository) DB() *gorm.DB { return r.db }

// WithTx 返回绑定到指定事务的仓储聚合。
//
// 这是本项目处理跨表事务的统一方式：service 层调用
//
//	err := repo.DB().Transaction(func(tx *gorm.DB) error {
//	    txRepo := repo.WithTx(tx)
//	    ...
//	})
//
// 从而保证事务内的每一步读写都落在同一个连接上。
func (r *Repository) WithTx(tx *gorm.DB) *Repository {
	return &Repository{
		db:          tx,
		User:        NewUserRepository(tx),
		Role:        NewRoleRepository(tx),
		Session:     NewSessionRepository(tx),
		Audit:       NewAuditRepository(tx),
		Asset:       NewAssetRepository(tx),
		AssetGroup:  NewAssetGroupRepository(tx),
		Dictionary:  NewDictionaryRepository(tx),
		ScanFile:    NewScanFileRepository(tx),
		Vuln:        NewVulnRepository(tx),
		Assessment:  NewAssessmentRepository(tx),
		SystemCfg:   NewSystemConfigRepository(tx),
		Remediation: NewRemediationRepository(tx),
		Integration: NewIntegrationRepository(tx),
	}
}

// Transaction 在事务内执行 fn。
func (r *Repository) Transaction(ctx context.Context, fn func(txRepo *Repository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(r.WithTx(tx))
	})
}
