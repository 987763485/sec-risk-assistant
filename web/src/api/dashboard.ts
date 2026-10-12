/**
 * 首页统计接口（只读聚合）。
 *
 * ▍这个接口最重要的性质：风险数字**绑定一个具体评估**
 *
 * 同一句「很高风险有多少条」，在四种口径下是四个不同的数字。
 * 因此风险区块的数字全部来自 `assessments.latest`，而后者带回
 * 评估的 ID / 名称 / 计算时间——**界面上必须把这三项显示出来**，
 * 否则那串数字没有意义（`@/views/dashboard/DashboardView.vue`
 * 把口径写在区块标题旁边，而不是藏在 tooltip 里）。
 *
 * 资产 / 漏洞 / 整改单是**全局当前态**，与评估口径无关。
 */
import type { DashboardSummary } from './endpoints'
import { api } from './http'
import { toQueryString } from './query'

/**
 * 读取首页汇总。
 *
 * @param assessmentId 不传表示取「最近一次**已计算**的评估」。
 *   显式传入但不存在时后端返回 404；传入一份草稿是允许的，
 *   此时风险区块按「尚未计算」返回全零并带上 `status: draft`，
 *   前端据此显示「这份评估还没算过」而不是「风险为零」。
 *
 * ⚠️ 后端按 `calculated_at DESC, id DESC` 挑「最近一次」而**不是按 id**：
 * 手工补算过的老任务会拿到更大的 id，但它不是最新结论。
 */
export function getDashboardSummary(assessmentId?: number): Promise<DashboardSummary> {
  return api.get<DashboardSummary>(
    `/dashboard/summary${toQueryString({ assessment_id: assessmentId })}`,
  )
}

/**
 * 漏洞严重程度档位 → 中文。
 *
 * 与风险等级（R 的档位）是两套不同的刻度：这里是漏洞自身的严重程度
 * （1–5），那里是 `R = A × T × V` 算出来的五档。界面上不能混用标签。
 */
export const SEVERITY_LABELS: Record<number, string> = {
  5: '严重',
  4: '高危',
  3: '中危',
  2: '低危',
  1: '信息',
}

/** 严重程度档位 → 色板（与风险等级色板刻意不同：两套刻度的颜色混用会误导） */
export const SEVERITY_COLORS: Record<number, string> = {
  5: '#c45656',
  4: '#e6a23c',
  3: '#d9b64a',
  2: '#79bbff',
  1: '#dcdcdc',
}
