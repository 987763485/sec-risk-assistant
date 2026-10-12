/**
 * 接口类型的统一出口。
 *
 * 全部类型都由 `src/api/generated/schema.d.ts` 派生，而后者由
 * `docs/openapi.yaml` 生成（`make api`）。因此这里的每一行都是
 * 「契约 → 类型」的搬运，不含任何手写结构——
 * 手写一份接口类型就等于手写了第二份契约，两份必然失配。
 *
 * 之所以还要包一层：让业务代码 import 自 `@/api/endpoints` 而不是
 * `@/api/generated/schema`。这样将来更换生成器或调整生成选项时，
 * 只需改这一个文件，业务代码零改动。
 */
import type { components, operations, paths } from './generated/schema'

/** 契约中的全部 schema */
export type Schemas = components['schemas']

// ---------------------------------------------------------------- 认证
export type Session = Schemas['Session']
export type SessionUser = Schemas['SessionUser']
export type Me = Schemas['Me']
export type CsrfToken = Schemas['CsrfToken']
export type LoginRequest = Schemas['LoginRequest']
export type ChangePasswordRequest = Schemas['ChangePasswordRequest']

/**
 * 权限码联合类型。
 *
 * 写成联合类型而不是 string，是为了让 `can('user:raed')` 这类拼写错误
 * 在编译期就被拦下——权限码拼错的表现是「菜单莫名消失」，
 * 这类问题在运行时排查起来非常费时。
 */
export type PermissionCode = Schemas['PermissionCode']

/** 业务错误码联合类型，供 switch 分支穷尽性检查 */
export type ErrorCode = Schemas['ErrorCode']

// ---------------------------------------------------------------- 用户
export type UserDetail = Schemas['UserDetail']
export type UserStatus = Schemas['UserStatus']
export type Role = Schemas['Role']
export type RoleBrief = Schemas['RoleBrief']
export type UserPage = Schemas['UserPage']
export type RoleList = Schemas['RoleList']
export type CreateUserRequest = Schemas['CreateUserRequest']
export type UpdateUserRequest = Schemas['UpdateUserRequest']
export type ResetPasswordRequest = Schemas['ResetPasswordRequest']

// ---------------------------------------------------------------- 审计
export type AuditLog = Schemas['AuditLog']
export type AuditLogPage = Schemas['AuditLogPage']

/** 审计动作码（契约中以枚举形式描述，此处提取为字符串联合便于前端筛选） */
export type AuditAction = NonNullable<
  paths['/api/audit-logs']['get']['parameters']['query']
>['action']

// ---------------------------------------------------------------- 业务字典
export type Dictionary = Schemas['Dictionary']
export type DictionaryList = Schemas['DictionaryList']
export type DictionaryCategory = Schemas['DictionaryCategory']
export type CreateDictionaryRequest = Schemas['CreateDictionaryRequest']
export type UpdateDictionaryRequest = Schemas['UpdateDictionaryRequest']

// ---------------------------------------------------------------- 资产分组
export type AssetGroup = Schemas['AssetGroup']
export type AssetGroupList = Schemas['AssetGroupList']
export type CreateAssetGroupRequest = Schemas['CreateAssetGroupRequest']
export type UpdateAssetGroupRequest = Schemas['UpdateAssetGroupRequest']
export type MoveAssetGroupRequest = Schemas['MoveAssetGroupRequest']

// ---------------------------------------------------------------- 资产台账
export type Asset = Schemas['Asset']
export type AssetPage = Schemas['AssetPage']
export type AssetStatus = Schemas['AssetStatus']
export type CreateAssetRequest = Schemas['CreateAssetRequest']
export type UpdateAssetRequest = Schemas['UpdateAssetRequest']

// ---------------------------------------------------------------- 批量导入
export type AssetImportPreview = Schemas['AssetImportPreview']
export type AssetImportResult = Schemas['AssetImportResult']
export type ImportRowError = Schemas['ImportRowError']

// ---------------------------------------------------------------- 扫描文件
export type ScanFile = Schemas['ScanFile']
export type ScanFilePage = Schemas['ScanFilePage']
export type ScanParseStatus = Schemas['ScanParseStatus']
export type UploadScanFileResult = Schemas['UploadScanFileResult']

// ---------------------------------------------------------------- 漏洞解析
export type ParseRequest = Schemas['ParseRequest']
export type ParseRowError = Schemas['ParseRowError']
export type VulnParsePreview = Schemas['VulnParsePreview']
export type VulnParseResult = Schemas['VulnParseResult']

// ---------------------------------------------------------------- 漏洞清单
export type Vulnerability = Schemas['Vulnerability']
export type VulnerabilityDetail = Schemas['VulnerabilityDetail']
export type VulnAsset = Schemas['VulnAsset']
export type VulnPage = Schemas['VulnPage']
export type CreateVulnerabilityRequest = Schemas['CreateVulnerabilityRequest']
export type UpdateVulnerabilityRequest = Schemas['UpdateVulnerabilityRequest']
export type SetVulnAssetsRequest = Schemas['SetVulnAssetsRequest']

// ---------------------------------------------------------------- 风险评估
export type Assessment = Schemas['Assessment']
export type AssessmentPage = Schemas['AssessmentPage']
export type AssessmentStatus = Schemas['AssessmentStatus']
export type AssessmentScopeType = Schemas['AssessmentScopeType']
export type AssessmentAssetSummary = Schemas['AssessmentAssetSummary']
export type AssessmentExportData = Schemas['AssessmentExportData']
export type CreateAssessmentRequest = Schemas['CreateAssessmentRequest']
export type UpdateAssessmentRequest = Schemas['UpdateAssessmentRequest']
export type PreviewAssessmentRequest = Schemas['PreviewAssessmentRequest']
export type PreviewAssessmentResult = Schemas['PreviewAssessmentResult']
export type ExportAssessmentMeta = Schemas['ExportAssessmentMeta']
export type ExportAsset = Schemas['ExportAsset']

/**
 * 风险等级联合类型。
 *
 * 它同时是前端**唯一**的风险判定输入：色板、标签、排序全部按这个字符串
 * 查表，代码里不存在任何 `r >= 20` 这类比较——判定只在后端发生
 * （docs/01 §2.6）。前端一旦自己算档位，就等于有了第二条判定路径，
 * 而它与后端分叉时不报错、只是颜色不对。
 */
export type RiskLevel = Schemas['RiskLevel']

export type RiskThresholds = Schemas['RiskThresholds']
export type RiskEngineSnapshot = Schemas['RiskEngineSnapshot']
export type RiskItem = Schemas['RiskItem']
export type RiskItemPage = Schemas['RiskItemPage']
export type RiskMatrix = Schemas['RiskMatrix']
export type RiskMatrixCell = Schemas['RiskMatrixCell']
export type SetRiskItemThreatRequest = Schemas['SetRiskItemThreatRequest']

// ---------------------------------------------------------------- 报告导出
export type ExportReportRequest = Schemas['ExportReportRequest']

/**
 * 报告导出格式。
 *
 * 三种格式在服务端走三条技术路线，**失败模式也不同**：`excel` 在 Go 进程内
 * 生成、不依赖上游，因此永远不会因为上游不可用而失败；`word` / `pdf` 分别
 * 依赖 docgen 与 Gotenberg，任一不可用即 503。前端据此给出的提示语也不同
 * （见 `@/api/reports` 的注释），所以这个类型不能退化成 string。
 */
export type ReportFormat = Schemas['ReportFormat']

// ---------------------------------------------------------------- 整改跟踪
export type Remediation = Schemas['Remediation']
export type RemediationPage = Schemas['RemediationPage']
export type RemediationDetail = Schemas['RemediationDetail']
export type RemediationLog = Schemas['RemediationLog']
export type RemediationTransitionOption = Schemas['RemediationTransitionOption']
export type CreateRemediationRequest = Schemas['CreateRemediationRequest']
export type UpdateRemediationRequest = Schemas['UpdateRemediationRequest']
export type TransitionRemediationRequest = Schemas['TransitionRemediationRequest']
export type BatchCreateRemediationRequest = Schemas['BatchCreateRemediationRequest']
export type BatchCreateRemediationResult = Schemas['BatchCreateRemediationResult']

/**
 * 整改单状态联合类型。
 *
 * 与 `RiskLevel` 同理：状态机**只在后端存在**，前端拿到的每个状态都是
 * 一个字符串，操作按钮由视图里的 `transitions`（后端投影）驱动。
 * 前端一旦自己写一份「pending 之后能到哪」的规则，就多了一条会静默
 * 分叉的判定路径——表现是按钮点了报 409，而按钮看起来完全正常。
 */
export type RemediationStatus = Schemas['RemediationStatus']

// ---------------------------------------------------------------- 首页统计
export type DashboardSummary = Schemas['DashboardSummary']
export type DashboardAssets = Schemas['DashboardAssets']
export type DashboardNamedCount = Schemas['DashboardNamedCount']
export type DashboardVulnerabilities = Schemas['DashboardVulnerabilities']
export type DashboardSeverityCount = Schemas['DashboardSeverityCount']
export type DashboardAssessments = Schemas['DashboardAssessments']
export type DashboardLatestAssessment = Schemas['DashboardLatestAssessment']
export type DashboardTopAsset = Schemas['DashboardTopAsset']
export type DashboardRemediations = Schemas['DashboardRemediations']

// ---------------------------------------------------------------- 情报源集成（P7）
export type Integration = Schemas['Integration']
export type IntegrationList = Schemas['IntegrationList']
export type IntegrationTypeOption = Schemas['IntegrationTypeOption']
export type CreateIntegrationRequest = Schemas['CreateIntegrationRequest']
export type UpdateIntegrationRequest = Schemas['UpdateIntegrationRequest']
export type FetchVulnIntelRequest = Schemas['FetchVulnIntelRequest']
export type FetchVulnIntelResult = Schemas['FetchVulnIntelResult']
export type FetchFailure = Schemas['FetchFailure']
export type VulnIntel = Schemas['VulnIntel']

/**
 * 适配器类型联合类型。
 *
 * 与 `PermissionCode` 同理：从契约派生而不是手写 `'nvd' | 'local'`。
 * 但**运行时一律以 `IntegrationList.supported_types` 为准**——
 * 类型是后端适配器的事实，前端类型联合只负责编译期收窄，
 * 两者不能互为替代（新增适配器时下拉框要自动多一项）。
 */
export type IntegrationType = Integration['type']

/**
 * 集成最近一次拉取的判定结果。空串表示从未拉取过——
 * 所以它不是简单的布尔，不能用 `!!last_status` 判断「是否成功」。
 */
export type IntegrationLastStatus = Integration['last_status']

/**
 * 情报严重度联合类型。
 *
 * 这是**上游说的**严重度（快照入库存下来），不是本地按 CVSS 分数现算的：
 * 现算会让同一行里出现「上游标 high、我们算出 medium」两个互相矛盾的答案。
 */
export type IntelSeverity = VulnIntel['severity']

// ---------------------------------------------------------------- 系统配置
export type SystemConfigView = Schemas['SystemConfigView']
export type SystemConfigItem = Schemas['SystemConfigItem']
export type UpdateSystemConfigRequest = Schemas['UpdateSystemConfigRequest']

// ---------------------------------------------------------------- 探针
export type HealthReady = Schemas['HealthReady']
export type HealthLive = Schemas['HealthLive']
export type VersionInfo = Schemas['VersionInfo']

/** 契约中的全部操作，供需要按 operationId 取类型的场景使用 */
export type ApiOperations = operations
/** 契约中的全部路径 */
export type ApiPaths = paths
