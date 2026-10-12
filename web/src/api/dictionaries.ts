import { api } from './http'
import type {
  CreateDictionaryRequest,
  Dictionary,
  DictionaryCategory,
  DictionaryList,
  UpdateDictionaryRequest,
} from './endpoints'

/**
 * 业务字典接口。
 *
 * 字典维护页与资产表单共用这两个读接口。字段名统一 snake_case，
 * 与契约逐字一致，不在这一层做命名转换。
 */

/**
 * 查询字典项。
 *
 * @param category    类别；省略表示全部类目
 * @param enabledOnly true 只返回启用项（资产表单用），
 *                    false 含停用项（字典维护页用，否则停用项会「凭空消失」）
 */
export async function listDictionaries(
  category?: DictionaryCategory,
  enabledOnly = false,
): Promise<Dictionary[]> {
  const query = new URLSearchParams()
  if (category) query.set('category', category)
  // 只在需要时显式传 true：后端默认返回含停用项的全部，
  // 前端不传这个参数时就不该有隐式行为
  if (enabledOnly) query.set('enabled', 'true')

  const suffix = query.size > 0 ? `?${query}` : ''
  const res = await api.get<DictionaryList>(`/dictionaries${suffix}`)
  return res.items ?? []
}

export function createDictionary(payload: CreateDictionaryRequest): Promise<Dictionary> {
  return api.post<Dictionary>('/dictionaries', payload)
}

export function updateDictionary(
  id: number,
  payload: UpdateDictionaryRequest,
): Promise<Dictionary> {
  return api.patch<Dictionary>(`/dictionaries/${id}`, payload)
}

export function deleteDictionary(id: number): Promise<void> {
  return api.delete<void>(`/dictionaries/${id}`)
}

/** 类别 → 中文名。用于分栏标题与表格里的类别列。 */
export const DICTIONARY_CATEGORY_LABELS: Record<DictionaryCategory, string> = {
  asset_type: '资产类型',
  threat: '威胁',
  vulnerability: '脆弱性',
  measure: '已有措施',
}

/**
 * 类别的权重语义说明。
 *
 * 四类共用一张表与一个 `weight` 列，因此维护界面上必须逐类说清这一列
 * 到底表示什么——否则用户会把「防护有效性」当成「严重程度」来填。
 */
export const DICTIONARY_CATEGORY_HINTS: Record<DictionaryCategory, string> = {
  asset_type: '不参与风险计算，权重固定为 1',
  threat: '权重 = 威胁发生可能性 T（1–5，越大越可能发生）',
  vulnerability: '权重 = 脆弱性严重程度 V（1–5，越大越严重）',
  measure: '权重 = 防护有效性（1–5，越大防护越强）',
}
