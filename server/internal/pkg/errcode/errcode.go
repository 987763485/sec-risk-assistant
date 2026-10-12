// Package errcode 集中定义业务错误码。
//
// 错误码是前后端契约的一部分：前端依据 code 决定是「弹提示」「跳登录」
// 还是「刷新令牌重试」，而不是去解析 message 的文案。
// 因此 message 可以随时改，code 一经发布不得随意变更。
//
// ▍新增错误码时必须做的两件事
//
//  1. 在下面的常量里加一个；
//  2. 把它登记进 allCodes，并同步补进 docs/openapi.yaml 的 ErrorCode 枚举。
//
// 这两步都有自动化守门，漏了会直接让测试变红：
//   - TestAllCodesCoversEveryConstant（本包）用 go/ast 解析本包源码，
//     逐个核对每个字符串常量是否出现在 allCodes 里；
//   - TestErrorCodeEnumCoversRegistry（internal/router）双向核对
//     allCodes 与契约的 ErrorCode 枚举。
//
// 之所以要这两道而不是只留一道：前者防「加了码但注册表漏了」，
// 后者防「注册表与契约漂移」，两种漏法方向相反。
package errcode

// 通用错误码。
const (
	// CodeOK 成功。统一响应包中 code 为 OK 时 data 才有意义。
	CodeOK = "OK"

	CodeInvalidParam    = "INVALID_PARAM"
	CodeUnauthorized    = "UNAUTHORIZED"
	CodeForbidden       = "FORBIDDEN"
	CodeNotFound        = "NOT_FOUND"
	CodeConflict        = "CONFLICT"
	CodeTooManyRequests = "TOO_MANY_REQUESTS"
	CodeInternal        = "INTERNAL_ERROR"
)

// 认证与会话错误码。
const (
	// CodeInvalidCredentials 用户名或密码错误。
	// ⚠️ 用户名不存在与密码错误必须返回**同一个码**，否则接口会变成
	// 「账号枚举器」，攻击者可据此逐个确认哪些用户名有效。
	CodeInvalidCredentials = "AUTH_INVALID_CREDENTIALS"

	// CodeAccountLocked 账号因连续登录失败被临时锁定
	CodeAccountLocked = "AUTH_ACCOUNT_LOCKED"
	// CodeAccountDisabled 账号已被管理员禁用
	CodeAccountDisabled = "AUTH_ACCOUNT_DISABLED"
	// CodeTokenExpired 访问令牌过期。前端据此静默刷新后重试。
	CodeTokenExpired = "AUTH_TOKEN_EXPIRED"
	// CodeTokenInvalid 令牌无效（签名错误、被吊销、格式非法）
	CodeTokenInvalid = "AUTH_TOKEN_INVALID"
	// CodeCSRFInvalid CSRF 双提交令牌缺失或不匹配
	CodeCSRFInvalid = "AUTH_CSRF_INVALID"
	// CodePasswordWeak 新密码不满足强度要求
	CodePasswordWeak = "AUTH_PASSWORD_WEAK"
	// CodePasswordMismatch 原密码校验失败
	CodePasswordMismatch = "AUTH_PASSWORD_MISMATCH"
	// CodeMustChangePassword 必须先修改初始密码
	CodeMustChangePassword = "AUTH_MUST_CHANGE_PASSWORD"
	// CodePasswordUnchanged 新密码与原密码相同
	CodePasswordUnchanged = "AUTH_PASSWORD_UNCHANGED"
)

// 用户管理错误码。
const (
	CodeUsernameTaken = "USER_USERNAME_TAKEN"
	CodeEmailTaken    = "USER_EMAIL_TAKEN"
	// CodeLastAdmin 试图移除系统中最后一个可用管理员
	CodeLastAdmin = "USER_LAST_ADMIN"
	// CodeSelfOperation 试图对自己执行禁用等危险操作
	CodeSelfOperation = "USER_SELF_OPERATION"
	// CodeRoleNotAssignable 指定的角色不存在或不可分配
	CodeRoleNotAssignable = "USER_ROLE_NOT_ASSIGNABLE"
)

// 资产与资产组错误码。
const (
	// CodeAssetNotFound 资产不存在
	CodeAssetNotFound = "ASSET_NOT_FOUND"
	// CodeAssetNoTaken 资产编号已被占用
	CodeAssetNoTaken = "ASSET_NO_TAKEN"
	// CodeAssetTypeUnknown 资产类型码不在字典中或已被停用。
	// 与「参数格式错误」分开：这是「字典里没有这个类型」，
	// 前端应当引导用户去字典维护页补一个，而不是让他反复改输入。
	CodeAssetTypeUnknown = "ASSET_TYPE_UNKNOWN"

	// CodeAssetGroupNotFound 资产组不存在
	CodeAssetGroupNotFound = "ASSET_GROUP_NOT_FOUND"
	// CodeAssetGroupNameTaken 同一父组下已有同名资产组
	CodeAssetGroupNameTaken = "ASSET_GROUP_NAME_TAKEN"
	// CodeAssetGroupHasChildren 资产组仍有子组，不能删除
	CodeAssetGroupHasChildren = "ASSET_GROUP_HAS_CHILDREN"
	// CodeAssetGroupHasAssets 资产组下仍有资产，不能删除
	CodeAssetGroupHasAssets = "ASSET_GROUP_HAS_ASSETS"
	// CodeAssetGroupCycle 不能把资产组移动到它自己的子孙之下
	CodeAssetGroupCycle = "ASSET_GROUP_CYCLE"
	// CodeAssetGroupDepthExceeded 层级超过上限
	CodeAssetGroupDepthExceeded = "ASSET_GROUP_DEPTH_EXCEEDED"
)

// 资产批量导入错误码。
//
// 这一组码刻意分得比较细：导入失败的原因直接决定用户下一步做什么
// （换文件 / 补列 / 改单元格 / 等一会儿），合成一个码就只能靠 message 猜。
const (
	// CodeImportFileMissing 未上传文件
	CodeImportFileMissing = "ASSET_IMPORT_FILE_MISSING"
	// CodeImportFileTooLarge 文件超过体积上限
	CodeImportFileTooLarge = "ASSET_IMPORT_FILE_TOO_LARGE"
	// CodeImportFormatInvalid 文件无法解析（不是 xlsx/csv、已损坏、无表头）
	CodeImportFormatInvalid = "ASSET_IMPORT_FORMAT_INVALID"
	// CodeImportMissingColumns 缺少必需列，message 里会列出缺了哪几列
	CodeImportMissingColumns = "ASSET_IMPORT_MISSING_COLUMNS"
	// CodeImportNoRows 文件里一行数据都没有（只有表头或全空）
	CodeImportNoRows = "ASSET_IMPORT_NO_ROWS"
	// CodeImportTooManyRows 数据行数超过上限
	CodeImportTooManyRows = "ASSET_IMPORT_TOO_MANY_ROWS"
	// CodeImportHasErrors 存在校验不通过的行。
	// commit 阶段返回这个码时**一条都不会入库**，data 里带完整行级错误。
	CodeImportHasErrors = "ASSET_IMPORT_HAS_ERRORS"
	// CodeImportGroupNotFound commit 时未勾选「自动创建缺失资产组」，
	// 而文件里引用了不存在的资产组
	CodeImportGroupNotFound = "ASSET_IMPORT_GROUP_NOT_FOUND"
)

// 业务字典错误码。
const (
	// CodeDictionaryNotFound 字典项不存在
	CodeDictionaryNotFound = "DICTIONARY_NOT_FOUND"
	// CodeDictionaryCategoryInvalid 字典类别非法
	CodeDictionaryCategoryInvalid = "DICTIONARY_CATEGORY_INVALID"
	// CodeDictionaryCodeTaken 同一类别下该码已存在
	CodeDictionaryCodeTaken = "DICTIONARY_CODE_TAKEN"
	// CodeDictionaryCodeImmutable 字典码创建后不可修改
	CodeDictionaryCodeImmutable = "DICTIONARY_CODE_IMMUTABLE"
	// CodeDictionaryBuiltinReadonly 内置字典项不允许删除
	CodeDictionaryBuiltinReadonly = "DICTIONARY_BUILTIN_READONLY"
	// CodeDictionaryInUse 字典项仍被资产引用，不能删除（停用即可）
	CodeDictionaryInUse = "DICTIONARY_IN_USE"
)

// 文件与解析错误码。
//
// 与导入那组一样分得细：每个码对应「用户下一步该做什么」。
// 状态码语义：类型不合法 400、体积超限 413、冲突 409、
// 解析器不认识内容 415（Unsupported Media Type 的本义）。
const (
	// CodeFileNotFound 文件记录不存在
	CodeFileNotFound = "FILE_NOT_FOUND"
	// CodeFileTypeRejected 扩展名 / MIME / 魔数三重校验未通过
	CodeFileTypeRejected = "FILE_TYPE_REJECTED"
	// CodeFileTooLarge 文件体积超过单文件上限
	CodeFileTooLarge = "FILE_TOO_LARGE"
	// CodeFileAlreadyParsed 该文件已解析入库，不能重复 commit
	CodeFileAlreadyParsed = "FILE_ALREADY_PARSED"
	// CodeFileInUse 文件仍有漏洞引用，不能删除
	CodeFileInUse = "FILE_IN_USE"
	// CodeFileFormatUnknown 文件通过了上传校验，但没有解析器认领它的内容
	CodeFileFormatUnknown = "FILE_FORMAT_UNKNOWN"
	// CodeVulnNotFound 漏洞不存在
	CodeVulnNotFound = "VULN_NOT_FOUND"
	// CodeVulnHasErrors 解析存在不合格的条目，整批未写入，data 带完整预览
	CodeVulnHasErrors = "VULN_HAS_ERRORS"
	// CodeVulnNoRows 解析结果为空（XML 里没有漏洞条目 / 表格里只有表头）
	CodeVulnNoRows = "VULN_IMPORT_NO_ROWS"
	// CodeVulnMissingColumns 表格缺少必需列
	//
	// 与 ASSET_IMPORT_MISSING_COLUMNS 对称，刻意**不复用** CodeVulnNoRows：
	// 「表头少了一列」与「一行数据都没有」对用户是完全不同的两件事——
	// 前者要回去改表头，后者要回去看报告是不是空的。共用一个码会让前端
	// 只能弹一句含糊的提示，用户得自己猜是哪一种。
	CodeVulnMissingColumns = "VULN_IMPORT_MISSING_COLUMNS"
	// CodeVulnTooMany 解析结果条数超过上限
	CodeVulnTooMany = "VULN_IMPORT_TOO_MANY_ROWS"
)

// 风险评估错误码。
//
// 与前面几组一样按「用户下一步该做什么」分：范围为空要回去勾资产，
// 威胁不存在要回去改字典，配置不合法要找管理员。合成一个码只会让前端
// 弹一句谁都用不上的话。
const (
	// CodeAssessmentNotFound 评估任务不存在
	CodeAssessmentNotFound = "ASSESSMENT_NOT_FOUND"
	// CodeAssessmentScopeEmpty 评估范围内没有任何可评估的资产
	CodeAssessmentScopeEmpty = "ASSESSMENT_SCOPE_EMPTY"
	// CodeAssessmentExportTooLarge 一次导出的风险项条数超过上限。
	// 报告是一次性导出、没有分页，超限必须报错——**悄悄截断的报告
	// 比报错的报告危险得多**：它看起来是完整的。
	CodeAssessmentExportTooLarge = "ASSESSMENT_EXPORT_TOO_LARGE"

	// CodeRiskItemNotFound 风险项不存在
	CodeRiskItemNotFound = "RISK_ITEM_NOT_FOUND"

	// CodeRiskConfigInvalid 风险配置不合法（阈值倒序/重叠、权重非正、值非数字）。
	// 请求侧触发是 400，配置表自身损坏是 500，两者共用这个码——
	// 对用户而言下一步是一样的：去系统设置里看那四个阈值。
	CodeRiskConfigInvalid = "RISK_CONFIG_INVALID"
	// CodeRiskConfigReadonly 该配置项不允许在界面修改
	CodeRiskConfigReadonly = "RISK_CONFIG_READONLY"

	// CodeThreatNotFound 威胁码在字典中不存在或已停用
	CodeThreatNotFound = "THREAT_NOT_FOUND"
)

// 报告导出错误码（P5）。
//
// 只有两个，而且都刻意与「评估」那组分开：报告导出失败时，用户下一步要做的
// 是「等一会儿再点一次」，而评估相关的失败要他回去改数据。
const (
	// CodeReportNotCalculated 评估任务尚未计算，没有可导出的结论。
	//
	// 返回 409（Conflict）而不是 400：请求本身完全合法，
	// 只是**当前状态**不允许。前端据此把「导出」按钮置灰并提示先计算，
	// 而不是让用户反复检查自己哪里填错了。
	CodeReportNotCalculated = "REPORT_NOT_CALCULATED"

	// CodeReportRenderFailed 渲染上游（docgen / Gotenberg）不可用。
	//
	// ⚠️ 必须是 503 而不是 500，因为这两句话对用户的天差地别：
	// 503 = 「服务在，只是这一刻不行，稍后重试大概率就好了」；
	// 500 = 「系统自己有毛病，再点也是白点」。
	// 报告渲染要起 .NET 进程与 Chromium 进程，是最容易偶发失败的一环，
	// 把这条路径笼统归成 500 会让「再点一次」这个正确动作被劝退。
	CodeReportRenderFailed = "REPORT_RENDER_FAILED"
)

// 整改跟踪错误码（P6）。
//
// 与前面几组一样按「用户下一步该做什么」分：重复建单要去看那张单子、
// 非法流转要回去看状态机、必填说明要给一句理由。合成一个
// 「整改单操作失败」会让前端只能弹一句谁都用不上的话。
const (
	// CodeRemediationNotFound 整改单不存在
	CodeRemediationNotFound = "REMEDIATION_NOT_FOUND"

	// CodeRemediationDuplicateActive 同一 (资产, 漏洞) 已存在一张**未闭环**的整改单。
	//
	// 返回 409 而不是 400：请求完全合法，只是当前状态不允许。
	// 前端据此把入口改成「打开已有单子」而不是让用户反复检查输入。
	// 这条规则由**数据库唯一索引**兜底（见迁移 000007 约束 2），
	// 服务层先查一次只是为了给出友好的错误，而不是唯一防线。
	CodeRemediationDuplicateActive = "REMEDIATION_DUPLICATE_ACTIVE"

	// CodeRemediationStatusInvalid 状态取值不在合法集合内
	CodeRemediationStatusInvalid = "REMEDIATION_STATUS_INVALID"

	// CodeRemediationTransitionInvalid 状态流转不被允许。
	//
	// 包括两类：状态机里没有这条边（如 pending → closed 需要先「已整改」），
	// 以及从**终态**（closed / accepted）往外流转——终态不可逆是刻意的，
	// 漏洞复发时应当新建一张单（见迁移 000007 约束 2）。
	CodeRemediationTransitionInvalid = "REMEDIATION_TRANSITION_INVALID"

	// CodeRemediationNoteRequired 该次流转必须填写说明。
	//
	// 三种情况命中：闭环（怎么修的）、风险接受（为什么不修）、
	// 打回（为什么不通过）。这三条都是**结论性**动作，
	// 当时不写，事后只剩一个状态变化，等于没留下可追溯的内容。
	CodeRemediationNoteRequired = "REMEDIATION_NOTE_REQUIRED"

	// CodeRemediationDeleteForbidden 该整改单不允许删除。
	//
	// 只有「待处理且从未流转」的单可以删——已经流转过的单是工作记录，
	// 删掉它就等于抹掉「有人承诺过要修、后来又改了口」这个事实。
	CodeRemediationDeleteForbidden = "REMEDIATION_DELETE_FORBIDDEN"

	// CodeRemediationBatchTooLarge 批量建单命中的风险项超过单次上限。
	//
	// 不静默截断：悄悄只建前 500 张，用户会以为其余的不需要整改。
	CodeRemediationBatchTooLarge = "REMEDIATION_BATCH_TOO_LARGE"

	// CodeRemediationBatchEmpty 按当前筛选条件没有任何可建单的风险项。
	//
	// 两种成因：评估尚未计算（没有风险项），或所选等级下确实一条都没有。
	// 两者对用户是同一件事——回去改筛选条件或先算一次。
	CodeRemediationBatchEmpty = "REMEDIATION_BATCH_EMPTY"
)

// allCodes 全部业务错误码的注册表。
//
// 它的唯一用途是「可被程序枚举」：OpenAPI 契约的 ErrorCode 枚举必须与它
// 完全一致，前端也据此生成联合类型。CodeOK 不在其中——它只出现在成功信封里。
var allCodes = []string{
	// 通用
	CodeInvalidParam,
	CodeUnauthorized,
	CodeForbidden,
	CodeNotFound,
	CodeConflict,
	CodeTooManyRequests,
	CodeInternal,

	// 认证与会话
	CodeInvalidCredentials,
	CodeAccountLocked,
	CodeAccountDisabled,
	CodeTokenExpired,
	CodeTokenInvalid,
	CodeCSRFInvalid,
	CodePasswordWeak,
	CodePasswordMismatch,
	CodeMustChangePassword,
	CodePasswordUnchanged,

	// 用户管理
	CodeUsernameTaken,
	CodeEmailTaken,
	CodeLastAdmin,
	CodeSelfOperation,
	CodeRoleNotAssignable,

	// 资产与资产组
	CodeAssetNotFound,
	CodeAssetNoTaken,
	CodeAssetTypeUnknown,
	CodeAssetGroupNotFound,
	CodeAssetGroupNameTaken,
	CodeAssetGroupHasChildren,
	CodeAssetGroupHasAssets,
	CodeAssetGroupCycle,
	CodeAssetGroupDepthExceeded,

	// 资产批量导入
	CodeImportFileMissing,
	CodeImportFileTooLarge,
	CodeImportFormatInvalid,
	CodeImportMissingColumns,
	CodeImportNoRows,
	CodeImportTooManyRows,
	CodeImportHasErrors,
	CodeImportGroupNotFound,

	// 业务字典
	CodeDictionaryNotFound,
	CodeDictionaryCategoryInvalid,
	CodeDictionaryCodeTaken,
	CodeDictionaryCodeImmutable,
	CodeDictionaryBuiltinReadonly,
	CodeDictionaryInUse,

	// 文件与解析
	CodeFileNotFound,
	CodeFileTypeRejected,
	CodeFileTooLarge,
	CodeFileAlreadyParsed,
	CodeFileInUse,
	CodeFileFormatUnknown,
	CodeVulnNotFound,
	CodeVulnHasErrors,
	CodeVulnNoRows,
	CodeVulnMissingColumns,
	CodeVulnTooMany,

	// 风险评估
	CodeAssessmentNotFound,
	CodeAssessmentScopeEmpty,
	CodeAssessmentExportTooLarge,
	CodeRiskItemNotFound,
	CodeRiskConfigInvalid,
	CodeRiskConfigReadonly,
	CodeThreatNotFound,

	// 报告导出
	CodeReportNotCalculated,
	CodeReportRenderFailed,

	// 整改跟踪
	CodeRemediationNotFound,
	CodeRemediationDuplicateActive,
	CodeRemediationStatusInvalid,
	CodeRemediationTransitionInvalid,
	CodeRemediationNoteRequired,
	CodeRemediationDeleteForbidden,
	CodeRemediationBatchTooLarge,
	CodeRemediationBatchEmpty,
}

// All 返回全部业务错误码的副本。
//
// 返回副本而不是原切片：调用方（契约校验测试）不该有能力改动全局注册表。
func All() []string {
	out := make([]string, len(allCodes))
	copy(out, allCodes)
	return out
}
