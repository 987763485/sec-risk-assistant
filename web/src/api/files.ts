import type { AxiosResponse } from 'axios'

import { http } from './client'
import type {
  ScanFile,
  ScanFilePage,
  ScanParseStatus,
  UploadScanFileResult,
  VulnParsePreview,
  VulnParseResult,
} from './endpoints'
import { api, HttpError } from './http'
import { toQueryString } from './query'

/** 扫描文件列表查询参数 */
export interface ScanFileListQuery {
  page?: number
  pageSize?: number
  /** 匹配原始文件名 */
  keyword?: string
  /** 解析状态过滤，不传表示全部 */
  parse_status?: ScanParseStatus
}

export function listScanFiles(query: ScanFileListQuery = {}): Promise<ScanFilePage> {
  return api.get<ScanFilePage>(`/files${toQueryString(query)}`)
}

export function getScanFile(id: number): Promise<ScanFile> {
  return api.get<ScanFile>(`/files/${id}`)
}

/**
 * 上传扫描报告。
 *
 * 组装 multipart 的规则见 assets.ts 的 buildImportForm：不设 Content-Type，
 * 交给浏览器补 boundary。体积上限 10 MB 由后端两道闸把关
 * （Content-Length 预检 + MaxBytesReader），前端不做预检——
 * 预检只多一段会漂移的重复逻辑，真正的事实以服务端为准。
 */
export function uploadScanFile(file: File): Promise<UploadScanFileResult> {
  const form = new FormData()
  form.append('file', file)
  return api.post<UploadScanFileResult>('/files/upload', form)
}

/**
 * 删除扫描文件。
 *
 * `force` 的语义见契约：文件已被解析出漏洞时（`vuln_count > 0`），
 * 默认删除会以 409 `FILE_IN_USE` 拒绝；显式传 `force=true` 才会在
 * 同一事务里级联删掉这些漏洞。前端不悄悄传 true——这是破坏性升级，
 * 必须由用户在确认框里明确选择。
 */
export function deleteScanFile(id: number, force = false): Promise<void> {
  return api.delete<void>(`/files/${id}${force ? '?force=true' : ''}`)
}

/**
 * 下载扫描报告原件（.nessus / .xml / .xlsx / .csv 原样取回）。
 *
 * 与模板下载同理：二进制响应不走信封拆解，直接用底层实例取 Blob。
 * 文件名以 `file.original_name` 为准——服务端回的 Content-Disposition
 * 就是按它生成的，正常情况两者一致。
 */
export async function downloadScanFile(file: ScanFile): Promise<Blob> {
  const res: AxiosResponse<Blob> = await http.get<Blob>(`/files/${file.id}/download`, {
    responseType: 'blob',
  })
  return res.data
}

// ------------------------------------------------------------------ 解析

/**
 * 解析预览（只读，不写任何数据）。
 *
 * 服务端不持有会话状态：同一个文件可以反复预览（比如先补了几条资产
 * 再看匹配情况）。**预览结果不会被 commit 复用**——commit 重新解析
 * 重新校验，预览只是给用户看的快照。
 */
export function previewParse(fileId: number): Promise<VulnParsePreview> {
  return api.post<VulnParsePreview>('/parser/preview', { file_id: fileId })
}

/**
 * 确认解析入库的结果。
 *
 * 「Excel 存在行级错误」不是异常而是正常结果分支（与资产导入同构）：
 * commit 是原子的，任一行不合格则一条不写，此时返回 409 +
 * `VULN_HAS_ERRORS`，响应体 `data` 里挂着完整预览，界面可以直接
 * 渲染出与预览阶段一致的错误表。
 */
export type CommitParseOutcome =
  | { ok: true; result: VulnParseResult }
  | { ok: false; reason: 'has_errors'; preview: VulnParsePreview }

export async function commitParse(fileId: number): Promise<CommitParseOutcome> {
  try {
    const result = await api.post<VulnParseResult>('/parser/commit', { file_id: fileId })
    return { ok: true, result }
  } catch (err) {
    if (err instanceof HttpError && err.code === 'VULN_HAS_ERRORS') {
      const preview = asParsePreview(err.data)
      if (preview) return { ok: false, reason: 'has_errors', preview }
    }
    throw err
  }
}

/** 把「未知形状」收敛成 VulnParsePreview（理由同 assets.ts 的 asImportPreview） */
export function asParsePreview(data: unknown): VulnParsePreview | null {
  if (typeof data !== 'object' || data === null) return null
  const candidate = data as Partial<VulnParsePreview>
  if (!Array.isArray(candidate.errors) || !Array.isArray(candidate.missing_columns)) return null
  return candidate as VulnParsePreview
}

// ------------------------------------------------------------------ 展示辅助

/** 解析状态 → 中文 */
export const PARSE_STATUS_LABELS: Record<ScanParseStatus, string> = {
  unparsed: '未解析',
  parsed: '已解析',
  failed: '解析失败',
}

/** 解析状态标签配色。failed 用 danger：它需要人来介入看日志或换文件 */
export const PARSE_STATUS_TAG_TYPE: Record<
  ScanParseStatus,
  'success' | 'info' | 'warning' | 'danger'
> = {
  unparsed: 'info',
  parsed: 'success',
  failed: 'danger',
}

/** 报告格式 → 中文。空串表示上传时没嗅探出来，不与「解析失败」混为一谈 */
export const FILE_FORMAT_LABELS: Record<string, string> = {
  nessus: 'Nessus',
  openvas: 'OpenVAS',
  excel: 'Excel / CSV',
  '': '未知',
}
