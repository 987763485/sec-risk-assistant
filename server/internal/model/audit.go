package model

import "time"

// 审计动作码。集中定义便于前端筛选与统计，也避免各处手写字符串拼错。
const (
	ActionAuthLogin          = "auth.login"
	ActionAuthLoginFailed    = "auth.login_failed"
	ActionAuthLogout         = "auth.logout"
	ActionAuthRefresh        = "auth.refresh"
	ActionAuthTokenReuse     = "auth.token_reuse_detected"
	ActionAuthPasswordChange = "auth.password_change"

	ActionUserCreate        = "user.create"
	ActionUserUpdate        = "user.update"
	ActionUserDisable       = "user.disable"
	ActionUserEnable        = "user.enable"
	ActionUserRoleUpdate    = "user.role_update"
	ActionUserPasswordReset = "user.password_reset"

	// ---- P2 资产与字典 ----
	//
	// 资产组用 asset_group.* 而不是 asset.group.*：动作码按「资源」分段，
	// 前缀一致才能在审计日志页按 `asset` 一眼筛出资产相关操作；
	// 而 asset_group 与 asset 是两个独立资源，硬塞进同一前缀会让
	// 「resource=asset」这个过滤条件把分组变更也算进来。
	ActionAssetCreate = "asset.create"
	ActionAssetUpdate = "asset.update"
	ActionAssetDelete = "asset.delete"
	// ActionAssetImport 批量导入。
	// 一次导入无论多少行都只留**一条**审计记录：500 条记录会把审计页
	// 冲成一个没法看的数据转储，而明细里的文件名与行数已经足够追溯。
	ActionAssetImport = "asset.import"

	ActionAssetGroupCreate = "asset_group.create"
	ActionAssetGroupUpdate = "asset_group.update"
	// ActionAssetGroupMove 调整资产组的父节点。
	// 与 update 分开是因为它的影响面完全不同：改名只动一行，
	// 移动会重写整棵子树的物化路径。审计里必须能一眼看出发生了哪种。
	ActionAssetGroupMove   = "asset_group.move"
	ActionAssetGroupDelete = "asset_group.delete"

	ActionDictionaryCreate = "dictionary.create"
	ActionDictionaryUpdate = "dictionary.update"
	ActionDictionaryDelete = "dictionary.delete"

	// ---- P3 文件与漏洞 ----
	ActionFileUpload = "file.upload"
	// ActionFileUploadDuplicate 同一内容重复上传（哈希命中，幂等返回）。
	// 与普通上传分开：审计要能回答「这份报告被谁传过几次」，
	// 但同时不能把重复上传伪装成新文件。
	ActionFileUploadDuplicate = "file.upload_duplicate"
	ActionFileDelete          = "file.delete"
	// ActionFileParse 解析入库（parser/commit）。一次 commit 一条记录。
	ActionFileParse = "file.parse"

	ActionVulnCreate = "vuln.create"
	ActionVulnUpdate = "vuln.update"
	ActionVulnDelete = "vuln.delete"
	ActionVulnLink   = "vuln.link"

	// ---- P4 风险评估 ----
	ActionAssessCreate = "assessment.create"
	ActionAssessUpdate = "assessment.update"
	ActionAssessDelete = "assessment.delete"
	// ActionAssessCalculate 计算落库。
	// 与 update 分开：它不改变任务定义，只重写结果集；而「这份报告的结论
	// 是哪一次计算产生的」是审计要能回答的问题。
	ActionAssessCalculate = "assessment.calculate"
	// ActionAssessItemUpdate 逐项覆盖某条风险项的威胁。
	// 单开一个动作而不是并入 assessment.update：它改的是结果不是定义，
	// 而且每改一条都会改变该资产的风险等级——值得逐条留痕。
	ActionAssessItemUpdate = "assessment.risk_item_update"
	// ActionAssessExport 导出报告数据。
	// 导出是敏感动作（数据离开系统边界），与「看一眼列表」不是一回事。
	ActionAssessExport = "assessment.export"

	// ActionSystemConfigUpdate 修改系统配置（当前只有风险模型的权重与阈值）。
	// ⚠️ 这一类操作会让**之后**的评估结果与之前的不可比，属高敏感操作。
	ActionSystemConfigUpdate = "system_config.update"

	// ---- P5 报告导出 ----
	//
	// ActionReportExport 渲染并下载报告文件（word / excel / pdf）。
	//
	// 与 ActionAssessExport 分开，因为它们**不是同一件事**：
	// assessment.export 是「把结构化数据取出来」（P4 的 export-data 接口，
	// 给脚本消费），report.export 是「生成一份可交付的文件」——后者是
	// 真正意义上的「数据离开系统边界」，一份带公司抬头的 PDF 会被转发出去。
	// 合成一个动作码，审计里就再也分不清「有人写了个脚本拉数据」与
	// 「有人导出了一份报告发给了客户」。
	ActionReportExport = "report.export"

	// ---- P6 整改跟踪 ----
	ActionRemediationCreate = "remediation.create"
	// ActionRemediationUpdate 改字段（负责人 / 期限 / 说明）。
	ActionRemediationUpdate = "remediation.update"
	// ActionRemediationTransition 状态流转。
	//
	// 与 update 分开，因为它才是整改跟踪的**主干动作**：审计要能回答
	// 「这张单子是谁在什么时候从『已整改』打回成『整改中』的」。
	// 答案若与「改了个期限」混在同一个动作码里，就需要把 detail 里的
	// JSON 全部读一遍才能筛出来。
	ActionRemediationTransition = "remediation.transition"
	// ActionRemediationDelete 删除误建的单。
	// 只在「待处理且从未流转」时允许（见 docs/13 D7），因此这个动作码
	// 出现得越少越好——它一出现就说明有人建错了单。
	ActionRemediationDelete = "remediation.delete"
	// ActionRemediationBatchCreate 批量建单。
	//
	// 与单张 create 分开、且一次批量只留**一条**记录，理由与
	// ActionAssetImport 完全相同：按「很高 + 高」批量建单一次可能产生
	// 几百张单，逐张留痕会把审计页冲成一个没法看的数据转储，
	// 而明细里的评估 ID 与条数已经足够追溯。
	ActionRemediationBatchCreate = "remediation.batch_create"
)

// AuditLog 审计日志。
//
// user_id 刻意不建外键：审计记录的留存优先级高于账号本身。
// username 做冗余存储，避免账号改名后历史日志无法对应到人。
type AuditLog struct {
	ID         uint64  `gorm:"column:id;primaryKey;autoIncrement"`
	UserID     *uint64 `gorm:"column:user_id"`
	Username   string  `gorm:"column:username;size:64"`
	Action     string  `gorm:"column:action;size:64"`
	Resource   string  `gorm:"column:resource;size:64"`
	ResourceID string  `gorm:"column:resource_id;size:64"`

	Method     string `gorm:"column:method;size:8"`
	Path       string `gorm:"column:path;size:255"`
	StatusCode int    `gorm:"column:status_code"`
	ClientIP   string `gorm:"column:client_ip;size:64"`
	UserAgent  string `gorm:"column:user_agent;size:255"`

	// Detail 变更明细（JSON）。用 *string 而不是 json.RawMessage：
	// 空值必须是 SQL NULL，而不是会被 MySQL 拒绝的非法 JSON 空串。
	Detail    *string   `gorm:"column:detail;type:json"`
	RequestID string    `gorm:"column:request_id;size:64"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

// TableName 指定表名。
func (AuditLog) TableName() string { return "audit_logs" }

// AuditEntry 待落库的审计记录。
//
// 定义在 model 而非 middleware，是为了让「中间件（生产者）、service（生产者）、
// repository（消费者）」三方都只依赖 model，不产生任何循环依赖。
type AuditEntry struct {
	// UserID 为 0 表示匿名操作（例如登录失败时尚未通过认证）
	UserID     uint64
	Username   string
	Action     string
	Resource   string
	ResourceID string
	Method     string
	Path       string
	StatusCode int
	ClientIP   string
	UserAgent  string
	// Detail 已序列化的 JSON 明细，nil 表示无明细
	Detail    []byte
	RequestID string
}
