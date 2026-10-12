import type {
  CreateVulnerabilityRequest,
  SetVulnAssetsRequest,
  UpdateVulnerabilityRequest,
  VulnAsset,
  Vulnerability,
  VulnerabilityDetail,
  VulnPage,
} from './endpoints'
import { api } from './http'
import { toQueryString } from './query'

/** 漏洞列表查询参数 */
export interface VulnListQuery {
  page?: number
  pageSize?: number
  /** 匹配名称 / CVE / 主机 IP / 来源文件名 / 描述 */
  keyword?: string
  /** 标准五级 1–5 */
  severity?: number
  /**
   * 来源文件过滤，**三态**：不传 = 不限来源；`0` = 只看手工录入；
   * `>0` = 只看该文件解析出的漏洞。与后端查询参数约定一一对应。
   */
  source_file_id?: number
  /** 只看已关联资产的 / 只看未关联的，不传表示全部 */
  linked?: boolean
}

export function listVulnerabilities(query: VulnListQuery = {}): Promise<VulnPage> {
  return api.get<VulnPage>(`/vulnerabilities${toQueryString(query)}`)
}

/** 漏洞详情（含关联资产，auto 与 manual 混排） */
export function getVulnerability(id: number): Promise<VulnerabilityDetail> {
  return api.get<VulnerabilityDetail>(`/vulnerabilities/${id}`)
}

export function createVulnerability(payload: CreateVulnerabilityRequest): Promise<Vulnerability> {
  return api.post<Vulnerability>('/vulnerabilities', payload)
}

/**
 * 编辑漏洞。
 *
 * `port` 是**三态**的（见契约 UpdateVulnerabilityRequest）：不传 = 不修改，
 * 显式 `null` = 清空，给值 = 设值。调用方提交的是「表单当前的完整状态」，
 * 因此清空端口时要显式传 `null` 而不是 `undefined`。
 *
 * `description` / `solution` 同样是三态（契约里是 `[string, "null"]`）。
 */
export function updateVulnerability(
  id: number,
  payload: UpdateVulnerabilityRequest,
): Promise<Vulnerability> {
  return api.patch<Vulnerability>(`/vulnerabilities/${id}`, payload)
}

export function deleteVulnerability(id: number): Promise<void> {
  return api.delete<void>(`/vulnerabilities/${id}`)
}

/**
 * 整体替换**手动**关联。
 *
 * `asset_ids` 是 manual 链接的最终状态而不是增量：传空数组 = 清空全部
 * 手动关联。**只影响 `matched_by = 'manual'` 的链接**，解析时按 IP
 * 建立的 auto 链接不受影响——手动操作无权覆盖解析结果。
 *
 * 因此调用方提交的必须是「手动关联」的集合，不能把详情里的全部资产
 * （含 auto）原样传回来：那会把 auto 链接的资产也写进 manual 意图里
 * （虽然唯一键会让重复插入被忽略，但语义已经错了）。
 */
export function setVulnerabilityAssets(
  id: number,
  payload: SetVulnAssetsRequest,
): Promise<{ assets: VulnAsset[] }> {
  return api.post<{ assets: VulnAsset[] }>(`/vulnerabilities/${id}/assets`, payload)
}

// ------------------------------------------------------------------ 展示辅助

/** 严重程度 1–5 的档位名。与扫描器的原始等级词（severity_raw）分开展示 */
export const SEVERITY_LABELS: Record<number, string> = {
  1: '信息',
  2: '低危',
  3: '中危',
  4: '高危',
  5: '严重',
}

/** 严重程度标签配色。按中文习惯从信息（灰）到严重（红）逐级加深 */
export const SEVERITY_TAG_TYPE: Record<number, 'info' | 'success' | 'warning' | 'danger'> = {
  1: 'info',
  2: 'success',
  3: 'warning',
  4: 'danger',
  5: 'danger',
}

/** 关联方式 → 中文 */
export const MATCHED_BY_LABELS: Record<string, string> = {
  auto: 'IP 自动匹配',
  manual: '手动关联',
}
