/**
 * 整改跟踪接口。
 *
 * ▍前端的三个约束（都来自后端的设计决定，不是这里的偏好）
 *
 * 1. **状态机不在前端**：能流转到哪由 `remediation.transitions` 给出。
 *    这个模块里不存在任何「pending 能到 in_progress」这类规则。
 * 2. **逾期不在前端算**：`overdue` / `overdue_days` / `due_in_days`
 *    三个字段由后端算好——「今天」只有一个来源（后端进程），
 *    前端按本地时区再算一次会让同一张单子在两个页面上一个逾期一个不逾期。
 * 3. **风险等级不在前端判**：`risk_level` 是字符串，这里只查色板。
 */
import type {
  BatchCreateRemediationRequest,
  BatchCreateRemediationResult,
  CreateRemediationRequest,
  Remediation,
  RemediationDetail,
  RemediationPage,
  RemediationStatus,
  RiskLevel,
  TransitionRemediationRequest,
  UpdateRemediationRequest,
} from './endpoints'
import { api } from './http'
import { toQueryString } from './query'

/** 整改单列表查询参数 */
export interface RemediationListQuery {
  page?: number
  pageSize?: number
  /** 按标题 / 资产名 / 资产 IP / 漏洞标题 / CVE 模糊匹配 */
  keyword?: string
  /** 按状态精确过滤（与 active 同时给出时以 active 为准） */
  status?: RemediationStatus
  /** 只看未闭环 */
  active?: boolean
  /** 只看已逾期 */
  overdue?: boolean
  assignee_id?: number
  level?: RiskLevel
  /** 按发现出处（评估任务）过滤 */
  assessment_id?: number
}

export function listRemediations(query: RemediationListQuery = {}): Promise<RemediationPage> {
  return api.get<RemediationPage>(`/remediations${toQueryString(query)}`)
}

export function getRemediation(id: number): Promise<RemediationDetail> {
  return api.get<RemediationDetail>(`/remediations/${id}`)
}

/**
 * 建单。
 *
 * `risk_item_id` 必填而不是资产 + 漏洞两个 ID：整改单要有风险等级与风险值，
 * 而这两者只有风险项才有（见契约里 `CreateRemediationRequest` 的说明）。
 * 同一 (资产, 漏洞) 已有未闭环单时后端返回 409
 * `REMEDIATION_DUPLICATE_ACTIVE`，文案里会说「请直接处理那张单子」——
 * 这里**不要**把它包装成「创建失败」，那句话就是用户需要看到的下一步。
 */
export function createRemediation(payload: CreateRemediationRequest): Promise<Remediation> {
  return api.post<Remediation>('/remediations', payload)
}

/**
 * 按评估任务批量建单。
 *
 * 幂等语义与单张建单**不同**：已有未闭环单的目标被跳过而不是报错，
 * 结果里的 `skipped` 给出条数。因此连续点两次不会失败，
 * 第二次是 `created=0 / skipped=N`。界面据此给出不同文案。
 */
export function batchCreateRemediations(
  payload: BatchCreateRemediationRequest,
): Promise<BatchCreateRemediationResult> {
  return api.post<BatchCreateRemediationResult>('/remediations/batch', payload)
}

/** 改字段（不含状态）。`assignee_id` / `due_date` 支持三态，见契约。 */
export function updateRemediation(
  id: number,
  payload: UpdateRemediationRequest,
): Promise<Remediation> {
  return api.patch<Remediation>(`/remediations/${id}`, payload)
}

/**
 * 状态流转。
 *
 * ⚠️ 不要在前端预先判断目标是否合法——视图里的 `transitions` 已经是
 * 那一份规则。这里传来的 `to_status` 若非法，后端会以 409 返回
 * 「当前可流转到：…」，那句话比前端猜的更准。
 */
export function transitionRemediation(
  id: number,
  payload: TransitionRemediationRequest,
): Promise<Remediation> {
  return api.post<Remediation>(`/remediations/${id}/transition`, payload)
}

export function deleteRemediation(id: number): Promise<void> {
  return api.delete<void>(`/remediations/${id}`)
}

// ------------------------------------------------------------------ 展示辅助
//
// 与 `@/api/assessments` 的展示辅助同一性质：全部是**查表**，没有比较运算。

/** 整改单状态 → 中文标签 */
export const REMEDIATION_STATUS_LABELS: Record<RemediationStatus, string> = {
  pending: '待处理',
  in_progress: '处理中',
  resolved: '待复核',
  closed: '已闭环',
  accepted: '风险接受',
}

/** 整改单状态 → Element Plus 标签配色 */
export const REMEDIATION_STATUS_TAG_TYPE: Record<
  RemediationStatus,
  'info' | 'primary' | 'warning' | 'success' | 'danger'
> = {
  pending: 'info',
  in_progress: 'primary',
  resolved: 'warning',
  closed: 'success',
  // 风险接受用 danger：它不是「做完了」，而是「决定不做」——
  // 在整改看板上它必须和「已闭环」一眼可分。
  accepted: 'danger',
}

/** 状态展示顺序：按流程走向，而不是按字母 */
export const REMEDIATION_STATUS_ORDER: RemediationStatus[] = [
  'pending',
  'in_progress',
  'resolved',
  'closed',
  'accepted',
]

/**
 * 整改单状态 → 图表底色。
 *
 * 与 `RISK_LEVEL_COLORS` 同一套做法（固定色阶、不插值），但**色板不同**：
 * 风险等级回答「有多严重」，整改状态回答「走到哪一步了」，用同一套颜色
 * 会让人以为「待处理」就等于「很高风险」。这里用的是中性到渐进的蓝绿系，
 * 只有「风险接受」用红——它不是「做完了」，而是「决定不做」。
 */
export const REMEDIATION_STATUS_COLORS: Record<RemediationStatus, string> = {
  pending: '#a0aec0',
  in_progress: '#409eff',
  resolved: '#e6a23c',
  closed: '#67c23a',
  accepted: '#c45656',
}

/** 流转记录动作 → 中文 */
export const REMEDIATION_LOG_ACTION_LABELS: Record<string, string> = {
  create: '建单',
  update: '变更',
  transition: '状态流转',
}

/** 流转记录动作 → 标签配色 */
export const REMEDIATION_LOG_ACTION_TAG_TYPE: Record<string, 'info' | 'primary' | 'success'> = {
  create: 'info',
  update: 'primary',
  transition: 'success',
}

/**
 * (资产, 漏洞) 的字符串键。
 *
 * 用它与后端整改单的业务身份保持一致（见契约 §路径说明）：
 * 整改单的身份是这一对 ID，不是 `risk_item_id`——后者在评估重算后
 * 整批失效，拿它做键会让状态列在重算之后全部变成「未建单」。
 */
export function remediationTargetKey(assetId: number, vulnId: number): string {
  return `${assetId}:${vulnId}`
}

/** 从整改单反推它对应的目标键（供结果页建索引） */
export function targetKeyOfRemediation(row: Remediation): string {
  return remediationTargetKey(row.asset_id, row.vuln_id)
}

/**
 * 加载全部**未闭环**整改单，按目标键索引。
 *
 * 评估结果页要显示「这条风险项有没有整改单」，而风险项逐页返回、
 * 整改单是另一个接口，两者没有共享的连接键。这里选择在**前端建索引**
 * 而不是加一个新接口：未闭环单的规模天然有限（它就是工作清单本身），
 * 翻页取回的代价可控，而多一个接口就多一份需要双向维护的契约。
 *
 * ⚠️ 只取未闭环单是有意的：闭环之后漏洞复发会**新建一张单**
 * （终态不可逆），此时「上一张已闭环」对当前这条风险项没有意义。
 *
 * `maxPages` 兜底防止某次数据异常把页面拖死；触顶时返回 `truncated=true`，
 * 由调用方在界面上明说「状态列可能不完整」，而不是静默少显示几张单子。
 */
export async function loadActiveRemediationMap(maxPages = 20): Promise<{
  map: Map<string, Remediation>
  truncated: boolean
}> {
  const map = new Map<string, Remediation>()
  const pageSize = 100
  let page = 1

  for (;;) {
    const res = await listRemediations({ active: true, page, pageSize })
    for (const row of res.items) map.set(targetKeyOfRemediation(row), row)

    // 三种收工条件：这一页空了（后端没有更多）、已取满、或触到页数上限。
    // 用 `map.size >= res.total` 而不是 `res.items.length < pageSize`：
    // 后者在「总数恰好是整页」时会多跑一次空请求。
    if (res.items.length === 0 || map.size >= res.total || page >= maxPages) {
      return { map, truncated: map.size < res.total }
    }
    page += 1
  }
}

/**
 * 时间态文案。
 *
 * 三态由后端算好，这里只做「哪个字段该显示」的选择：
 * 逾期看 `overdue_days`，未逾期看 `due_in_days`，没设期限看空。
 * 合成一个有符号数字（负号 = 逾期）能少一个字段，代价是每个调用方
 * 都要记得那个约定——忘了就会显示出「逾期 -3 天」。
 */
export function remediationTimingText(row: Remediation): string {
  if (row.status === 'closed' || row.status === 'accepted') return '已结束'
  if (row.due_date === null) return '未设期限'
  if (row.overdue) return `逾期 ${row.overdue_days} 天`
  if (row.due_in_days !== null && row.due_in_days === 0) return '今天到期'
  if (row.due_in_days !== null) return `还有 ${row.due_in_days} 天`
  return '—'
}

/**
 * 时间态配色。
 *
 * 逾期红、今天到期橙、其余中性——与仪表盘上的「逾期 / 即将到期」
 * 两个卡片用同一套语义，用户在两个页面看到的颜色含义是一致的。
 */
export function remediationTimingTagType(
  row: Remediation,
): 'danger' | 'warning' | 'info' | 'success' {
  if (row.status === 'closed' || row.status === 'accepted') return 'success'
  if (row.overdue) return 'danger'
  if (row.due_in_days !== null && row.due_in_days <= 3) return 'warning'
  return 'info'
}

/**
 * 已建单的提示文案。
 *
 * 「未建单」是结果页那一列的默认文案，这里把它抽出来是为了避免
 * 三处各写一遍中文字面量（两处不一致时用户会以为状态不同）。
 */
export const NO_REMEDIATION_TEXT = '未建单'
