import type {
  Assessment,
  AssessmentExportData,
  AssessmentPage,
  CreateAssessmentRequest,
  PreviewAssessmentRequest,
  PreviewAssessmentResult,
  RiskItem,
  RiskItemPage,
  RiskLevel,
  RiskMatrix,
  SetRiskItemThreatRequest,
  UpdateAssessmentRequest,
} from './endpoints'
import { api } from './http'
import { toQueryString } from './query'

/** 评估任务列表查询参数 */
export interface AssessmentListQuery {
  page?: number
  pageSize?: number
  /** 按名称 / 说明模糊匹配 */
  keyword?: string
  /** 按状态过滤，不传表示不限 */
  status?: 'draft' | 'calculated'
}

/** 风险项下钻查询参数（矩阵点击某格后带 importance + severity 过来） */
export interface RiskItemListQuery {
  page?: number
  pageSize?: number
  /** 资产重要性档位 1–5（矩阵横轴） */
  importance?: number
  /** 漏洞严重程度档位 1–5（矩阵纵轴） */
  severity?: number
  level?: RiskLevel
  keyword?: string
}

export function listAssessments(query: AssessmentListQuery = {}): Promise<AssessmentPage> {
  return api.get<AssessmentPage>(`/assessments${toQueryString(query)}`)
}

export function getAssessment(id: number): Promise<Assessment> {
  return api.get<Assessment>(`/assessments/${id}`)
}

export function createAssessment(payload: CreateAssessmentRequest): Promise<Assessment> {
  return api.post<Assessment>('/assessments', payload)
}

/**
 * 编辑评估任务。
 *
 * **改完不会自动重算**，也不会退回草稿：后端刻意不这么做，
 * 因为「改了参数」与「按新参数算出结果」是两件事。前端在保存后
 * 需要提示用户「参数已更新，结果仍是上一次计算的」。
 */
export function updateAssessment(
  id: number,
  payload: UpdateAssessmentRequest,
): Promise<Assessment> {
  return api.patch<Assessment>(`/assessments/${id}`, payload)
}

export function deleteAssessment(id: number): Promise<void> {
  return api.delete<void>(`/assessments/${id}`)
}

/**
 * 试算：**只读**，不落库、不写审计。
 *
 * 与 `calculate` 在服务端共用同一份计算实现，因此这里拿到的数字
 * 与计算后的落库值逐条一致——前端不需要（也不允许）自己再算一遍。
 */
export function previewAssessment(
  payload: PreviewAssessmentRequest,
): Promise<PreviewAssessmentResult> {
  return api.post<PreviewAssessmentResult>('/assessments/preview', payload)
}

/** 计算并落库。**幂等**：重复调用是覆盖而不是追加。 */
export function calculateAssessment(id: number): Promise<Assessment> {
  return api.post<Assessment>(`/assessments/${id}/calculate`, {})
}

export function listRiskItems(id: number, query: RiskItemListQuery = {}): Promise<RiskItemPage> {
  return api.get<RiskItemPage>(`/assessments/${id}/risk-items${toQueryString(query)}`)
}

/** 逐项覆盖某条风险项的威胁。服务端会立即重算该条与所在评估的汇总。 */
export function setRiskItemThreat(
  assessmentId: number,
  itemId: number,
  payload: SetRiskItemThreatRequest,
): Promise<RiskItem> {
  return api.patch<RiskItem>(`/assessments/${assessmentId}/risk-items/${itemId}`, payload)
}

export function getAssessmentMatrix(id: number): Promise<RiskMatrix> {
  return api.get<RiskMatrix>(`/assessments/${id}/matrix`)
}

/**
 * 导出报告数据。
 *
 * 返回的是 P5 报告渲染器将要消费的结构化数据，不是文档文件本身。
 * 它存在的意义是让「界面值 = 落库值 = 报告值」在 P4 就能验证。
 */
export function exportAssessmentData(id: number): Promise<AssessmentExportData> {
  return api.get<AssessmentExportData>(`/assessments/${id}/export-data`)
}

// ------------------------------------------------------------------ 展示辅助
//
// ⚠️ 这一节全部是**查表**，没有一处比较运算。
//
// 风险等级的判定完全在后端（docs/01 §2.6）：前端拿到的 `risk_level` 是
// 一个字符串，这里只负责把它翻译成标签、颜色、排序位置。任何
// 「if (r >= 20)」写法都会在系统里制造出第二条判定路径，而它与后端
// 分叉时不会报错——只是颜色和结论对不上。

/** 风险等级 → 中文标签 */
export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  very_high: '很高',
  high: '高',
  medium: '中',
  low: '低',
  very_low: '很低',
}

/** 风险等级 → Element Plus 标签配色 */
export const RISK_LEVEL_TAG_TYPE: Record<RiskLevel, 'danger' | 'warning' | 'info' | 'success'> = {
  very_high: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'success',
  very_low: 'info',
}

/**
 * 风险等级 → 热力图底色。
 *
 * 用固定色阶而不用连续插值：等级本身是离散的五档，让它看起来连续
 * 会诱导读者去比较颜色深浅的细微差别，而那是没有意义的。
 * 色相按「红—橙—黄—蓝—灰」递减严重程度。
 */
export const RISK_LEVEL_COLORS: Record<RiskLevel, string> = {
  very_high: '#c45656',
  high: '#e6a23c',
  medium: '#d9b64a',
  low: '#79bbff',
  very_low: '#dcdcdc',
}

/** 风险等级 → 文字色（在深色底上换白字，保证对比度） */
export const RISK_LEVEL_TEXT_COLORS: Record<RiskLevel, string> = {
  very_high: '#ffffff',
  high: '#ffffff',
  medium: '#4a3b00',
  low: '#1a3d5c',
  very_low: '#555555',
}

/** 风险等级展示顺序：从高到低（与后端 RiskLevels 的顺序一致） */
export const RISK_LEVEL_ORDER: RiskLevel[] = ['very_high', 'high', 'medium', 'low', 'very_low']

/** 评估任务状态 → 中文 */
export const ASSESSMENT_STATUS_LABELS: Record<string, string> = {
  draft: '草稿',
  calculated: '已计算',
}

/** 评估任务状态 → 标签配色 */
export const ASSESSMENT_STATUS_TAG_TYPE: Record<string, 'info' | 'success'> = {
  draft: 'info',
  calculated: 'success',
}

/** 范围类型 → 中文 */
export const SCOPE_TYPE_LABELS: Record<string, string> = {
  all: '全部资产',
  group: '按资产组',
  custom: '手工指定',
}

/** 威胁来源 → 中文 */
export const THREAT_SOURCE_LABELS: Record<string, string> = {
  default: '任务默认',
  manual: '逐项指定',
}

/** 等级条数（后端恒返回五个键）按从高到低展开成数组，供表格 / 图例渲染 */
export function levelCountEntries(counts: Record<string, number> | undefined) {
  return RISK_LEVEL_ORDER.map((level) => ({
    level,
    label: RISK_LEVEL_LABELS[level],
    color: RISK_LEVEL_COLORS[level],
    count: counts?.[level] ?? 0,
  }))
}
