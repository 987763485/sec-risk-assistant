// Package model 的整改跟踪模型定义。
package model

import "time"

// RemediationStatus 整改单状态。
//
// 用字符串而不是整数，理由与 RiskLevel / AssessmentStatus 一致：
// 运维直查数据库时能直接读懂，不必去翻一张映射表。
//
// ▍为什么是这五个而不是「待处理 / 已处理」两个
//
// 「状态流转可追溯」是 P6 的验收标志，而两个状态能承载的流转只有一次。
// 真正需要留痕的是这两处：
//
//	resolved → in_progress   验证不通过，**打回**重做
//	*        → accepted      决定「这个风险我们接受，不修」
//
// 前者是整改工作的核心监督动作；后者是政企场景下必然存在的结论
// （等保检查里叫「风险接受」），若只有 closed 一个出口，
// 「修好了」与「决定不修」在数据上就完全分不清了。
type RemediationStatus string

const (
	// RemediationPending 待处理：新建即此态。
	RemediationPending RemediationStatus = "pending"
	// RemediationInProgress 整改中。
	RemediationInProgress RemediationStatus = "in_progress"
	// RemediationResolved 已整改，待验证（尚未闭环）。
	RemediationResolved RemediationStatus = "resolved"
	// RemediationClosed 已闭环（验证通过）。终态。
	RemediationClosed RemediationStatus = "closed"
	// RemediationAccepted 风险接受（决定不修）。终态。
	RemediationAccepted RemediationStatus = "accepted"
)

// RemediationStatuses 全部状态，顺序即前端展示顺序（按流程先后）。
var RemediationStatuses = []RemediationStatus{
	RemediationPending, RemediationInProgress, RemediationResolved,
	RemediationClosed, RemediationAccepted,
}

// RemediationActiveStatuses 未闭环状态。
//
// ⚠️ 这个集合有**两个**消费者，且必须永远一致：
//  1. `remediations.active_key` 生成列里的 `status IN (...)`（迁移 000007 约束 2）；
//  2. 逾期判定（未闭环才可能逾期）。
//
// 第 1 处写在 SQL 里，改这里改不了它 —— 因此迁移 000007 的注释与
// docs/13 都必须同步点出「这是同一个集合」，否则会出现
// 「唯一索引认为已闭环、而服务层仍认为它未闭环」的分裂。
var RemediationActiveStatuses = []RemediationStatus{
	RemediationPending, RemediationInProgress, RemediationResolved,
}

// Valid 判断状态是否合法。
func (s RemediationStatus) Valid() bool {
	for _, v := range RemediationStatuses {
		if s == v {
			return true
		}
	}
	return false
}

// Terminal 判断是否为终态。终态不可再流转（见迁移 000007 约束 2）。
func (s RemediationStatus) Terminal() bool {
	return s == RemediationClosed || s == RemediationAccepted
}

// IsActive 判断是否未闭环。
func (s RemediationStatus) IsActive() bool {
	for _, v := range RemediationActiveStatuses {
		if s == v {
			return true
		}
	}
	return false
}

// remediationTransitions 合法流转表。
//
// 这是全系统唯一的状态机定义：service 层的流转校验、前端的「下一步可选动作」
// 都由它派生。**不在前端另写一份**——两份定义意味着「界面允许但接口拒绝」
// 或者反过来，而后者更糟：用户点下去才被拒绝。
//
// 这张表里每个允许项都有明确理由，不做「全都允许」的宽松实现：
//
//	pending    → in_progress  开始整改（从没有「进行中」的阶段进入）
//	pending    → resolved     直接完成（改一个配置就好的问题，不必先「进行中」）
//	pending    → accepted     一开始就决定接受风险
//	in_progress→ resolved     整改完成，等待验证
//	in_progress→ pending      退回未开始（分派错了 / 暂时搁置）
//	in_progress→ accepted     整改中途决定不修
//	resolved   → closed       验证通过，闭环
//	resolved   → in_progress  **打回**：验证不通过，重做（本表最重要的一条）
//	resolved   → accepted     验证时确认接受风险
//
// 终态（closed / accepted）没有任何出边，因而从这个 map 里读不到键。
var remediationTransitions = map[RemediationStatus][]RemediationStatus{
	RemediationPending: {
		RemediationInProgress, RemediationResolved, RemediationAccepted,
	},
	RemediationInProgress: {
		RemediationResolved, RemediationPending, RemediationAccepted,
	},
	RemediationResolved: {
		RemediationClosed, RemediationInProgress, RemediationAccepted,
	},
	RemediationClosed:   {},
	RemediationAccepted: {},
}

// NextStatuses 返回某状态可以流转到的状态集合（顺序固定，供前端渲染）。
//
// 返回副本：调用方不该有能力改动全局状态机。
func NextStatuses(from RemediationStatus) []RemediationStatus {
	src := remediationTransitions[from]
	out := make([]RemediationStatus, len(src))
	copy(out, src)
	return out
}

// CanTransition 判断状态流转是否合法。
func CanTransition(from, to RemediationStatus) bool {
	if from == to {
		return false
	}
	for _, v := range remediationTransitions[from] {
		if v == to {
			return true
		}
	}
	return false
}

// Remediation 整改单。
//
// AssetID / VulnID 是**业务身份**，AssessmentID / RiskItemID 只是**发现出处**
// （见迁移 000007 约束 1）。四个 ID 都是逻辑引用，没有外键；
// 展示一律走快照列。
//
// ⚠️ ActiveKey（迁移 000007 的生成列）刻意**不映射成字段**：
// 它是纯粹由数据库维护的不变量，GORM 若带着它去 INSERT 会被 MySQL 拒绝
// （「不允许为生成列指定值」）。它只存在于表结构里，不进入 Go 结构体。
type Remediation struct {
	ID uint64 `gorm:"column:id;primaryKey;autoIncrement"`

	// —— 业务身份 ——
	AssetID uint64 `gorm:"column:asset_id"`
	VulnID  uint64 `gorm:"column:vuln_id"`

	// —— 发现出处（允许失效）——
	AssessmentID *uint64 `gorm:"column:assessment_id"`
	RiskItemID   *uint64 `gorm:"column:risk_item_id"`

	// —— 快照列 ——
	AssetName  string  `gorm:"column:asset_name;size:128"`
	AssetIP    string  `gorm:"column:asset_ip;size:64"`
	VulnTitle  string  `gorm:"column:vuln_title;size:255"`
	VulnCVEIDs string  `gorm:"column:vuln_cve_ids;size:512"`
	RiskLevel  string  `gorm:"column:risk_level;size:16"`
	RiskValueR float64 `gorm:"column:risk_value_r"`

	// —— 单子内容 ——
	Title       string `gorm:"column:title;size:255"`
	Description string `gorm:"column:description;size:1000"`
	Resolution  string `gorm:"column:resolution;size:1000"`

	Status     RemediationStatus `gorm:"column:status;size:16"`
	AssigneeID *uint64           `gorm:"column:assignee_id"`
	// DueDate 可空。NULL = 未设期限，**永远不算逾期**——
	// 把「没设期限」当成「马上就到期」会让逾期数虚高，进而让这个指标失效。
	DueDate *time.Time `gorm:"column:due_date;type:date"`

	CreatedBy *uint64 `gorm:"column:created_by"`
	// ClosedAt 进入终态的时间（closed 与 accepted 共用）。
	ClosedAt *time.Time `gorm:"column:closed_at"`

	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName 指定表名。
func (Remediation) TableName() string { return "remediations" }

// Active 判断该单是否未闭环。与 Status.IsActive() 等价，
// 提供方法形式是为了让调用点读起来像在说业务（`r.Active()`）。
func (r *Remediation) Active() bool { return r.Status.IsActive() }

// RemediationLog 整改单的一条流转 / 变更记录。
//
// Action 三值见迁移 000007；FromStatus / ToStatus 只有 transition 才非空。
type RemediationLog struct {
	ID            uint64 `gorm:"column:id;primaryKey;autoIncrement"`
	RemediationID uint64 `gorm:"column:remediation_id"`

	Action     string `gorm:"column:action;size:16"`
	FromStatus string `gorm:"column:from_status;size:16"`
	ToStatus   string `gorm:"column:to_status;size:16"`
	Note       string `gorm:"column:note;size:500"`

	OperatorID   *uint64 `gorm:"column:operator_id"`
	OperatorName string  `gorm:"column:operator_name;size:64"`

	CreatedAt time.Time `gorm:"column:created_at"`
}

// TableName 指定表名。
func (RemediationLog) TableName() string { return "remediation_logs" }

// RemediationLogAction 日志动作的合法取值。
const (
	// RemediationLogCreate 建单
	RemediationLogCreate = "create"
	// RemediationLogUpdate 修改字段（负责人 / 期限 / 说明等）
	RemediationLogUpdate = "update"
	// RemediationLogTransition 状态流转
	RemediationLogTransition = "transition"
)
