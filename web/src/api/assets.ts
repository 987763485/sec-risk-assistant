import type { AxiosResponse } from 'axios'

import { http, HttpError } from './client'
import type {
  Asset,
  AssetImportPreview,
  AssetImportResult,
  AssetPage,
  AssetStatus,
  CreateAssetRequest,
  UpdateAssetRequest,
} from './endpoints'
import { api } from './http'
import { toQueryString } from './query'
import { filenameFromDisposition, type DownloadedFile } from '../utils/download'

/** 资产列表查询参数 */
export interface AssetListQuery {
  page?: number
  pageSize?: number
  /** 匹配名称 / 资产编号 / IP 地址 / 主机名 / 负责人 */
  keyword?: string
  /** 资产类型**码**，不是中文名 */
  asset_type?: string
  status?: AssetStatus
  /** 1–5 */
  importance?: number
  group_id?: number
  /**
   * 与 `group_id` 搭配：是否连子组的资产一起看。**默认 true**，
   * 这是后端定的默认值，前端不传就跟着走，不在这里再写一遍。
   */
  include_children?: boolean
}

export function listAssets(query: AssetListQuery = {}): Promise<AssetPage> {
  return api.get<AssetPage>(`/assets${toQueryString(query)}`)
}

export function getAsset(id: number): Promise<Asset> {
  return api.get<Asset>(`/assets/${id}`)
}

export function createAsset(payload: CreateAssetRequest): Promise<Asset> {
  return api.post<Asset>('/assets', payload)
}

/**
 * 编辑资产。
 *
 * `asset_no` / `group_id` / `port` 是**三态**的（见契约 UpdateAssetRequest）：
 * 不传 = 不修改，显式 `null` = 清空，给值 = 设值。调用方提交的是「表单当前的
 * 完整状态」，因此清空某个可选字段时要显式传 `null` 而不是 `undefined` ——
 * 后者会被理解为「别动这个字段」，用户会遇到「删了编号、保存后编号还在」。
 */
export function updateAsset(id: number, payload: UpdateAssetRequest): Promise<Asset> {
  return api.patch<Asset>(`/assets/${id}`, payload)
}

export function deleteAsset(id: number): Promise<void> {
  return api.delete<void>(`/assets/${id}`)
}

// ------------------------------------------------------------------ 批量导入
//
// 三个端点构成一条链路：下载模板 → 预览 → 确认导入。
// 预览与确认**都重新上传同一份文件**：服务端不持有导入会话状态（见契约里
// 对 commit 的说明），因此不能把 preview 的对象当作 commit 的入参传回去。

/** 模板下载的回退文件名。正常情况以服务端 Content-Disposition 里的名字为准。 */
export const DEFAULT_IMPORT_TEMPLATE_FILENAME = '资产导入模板.xlsx'

/**
 * 下载导入模板。
 *
 * **不走 `api.get`**：这是全系统唯一的二进制响应，套着统一 JSON 信封的
 * 拆解逻辑反而会把它拆坏（`isEnvelope` 对 Blob 返回 false，最终虽然也能
 * 透传出来，但「靠巧合正确」的代码不该留着）。这里直接用底层实例 +
 * `responseType: 'blob'`，意图明确。
 *
 * 这个方法返回数据而不触发下载：文件系统副作用（`<a download>`）留给
 * `@/utils/download`，api 层只管取数。
 */
export async function downloadImportTemplate(): Promise<DownloadedFile> {
  const res: AxiosResponse<Blob> = await http.get<Blob>('/assets/import/template', {
    responseType: 'blob',
  })
  return {
    blob: res.data,
    fileName:
      filenameFromDisposition(res.headers['content-disposition']) ??
      DEFAULT_IMPORT_TEMPLATE_FILENAME,
  }
}

/**
 * 组装 multipart 请求体。
 *
 * 刻意**不设 Content-Type**，且不能在调用处补一个 `multipart/form-data`：
 * multipart 的 Content-Type 必须带一个随机 boundary，而 boundary 只有
 * 浏览器在序列化 FormData 时才知道。手写一个不带 boundary 的
 * `multipart/form-data`，后端解析器会直接报「no multipart boundary param」。
 * axios 在浏览器环境下检测到原生 FormData 时会主动删掉这个头（见
 * axios/lib/helpers/resolveConfig.js），交给浏览器自己填。
 *
 * `create_missing_groups` 永远显式传值（而不是省略表示 false）：
 * 后端两阶段都要读它，省略与 false 虽然在当前实现下等价，但显式传值
 * 让请求体自证了「这一次到底按哪种口径校验」。
 */
function buildImportForm(file: File, createMissingGroups: boolean): FormData {
  const form = new FormData()
  form.append('file', file)
  form.append('create_missing_groups', createMissingGroups ? 'true' : 'false')
  return form
}

/**
 * 预览导入（不写入任何数据）。
 *
 * 文件级失败（缺列、格式不对、行数超限、文件缺失/过大）走错误投递，
 * 由调用方的 catch 处理；行级问题**不是错误**，而是正常返回值里的
 * `errors` 列表。
 */
export function previewAssetImport(
  file: File,
  createMissingGroups = false,
): Promise<AssetImportPreview> {
  return api.post<AssetImportPreview>(
    '/assets/import/preview',
    buildImportForm(file, createMissingGroups),
  )
}

/**
 * 确认导入的结果。
 *
 * 「存在不合格行」不是异常，而是导入操作的**正常结果之一**：用户点下确认
 * 按钮时，界面上本来就允许出现这种情况（例如两次点击之间，另一台机器占用了
 * 某个资产编号）。因此把它做成返回值的一个分支，而不是抛异常 ——
 * 抛异常会让调用代码长成 `try { ... } catch (e) { if (e.code === ...) }`，
 * 每个调用点都得记得去拆那个 if，漏掉的后果是「明明没导入进去，
 * 却弹了一句 success」。
 */
export type CommitImportOutcome =
  | { ok: true; result: AssetImportResult }
  | { ok: false; reason: 'has_errors'; preview: AssetImportPreview }

/**
 * 确认导入。
 *
 * 服务端保证**原子性**：任意一行不合格则一条都不写。此时返回 409 +
 * `ASSET_IMPORT_HAS_ERRORS`，响应体的 `data` 里挂着完整的预览结果，
 * 因此界面可以直接渲染出与预览阶段一模一样的错误表 —— 而不是只弹一句
 * 「导入失败」让用户回去重新猜哪里错了。
 *
 * 其余失败（`ASSET_IMPORT_GROUP_NOT_FOUND`、403、网络错误）照常抛出。
 */
export async function commitAssetImport(
  file: File,
  createMissingGroups = false,
): Promise<CommitImportOutcome> {
  try {
    const result = await api.post<AssetImportResult>(
      '/assets/import/commit',
      buildImportForm(file, createMissingGroups),
    )
    return { ok: true, result }
  } catch (err) {
    if (err instanceof HttpError && err.code === 'ASSET_IMPORT_HAS_ERRORS') {
      const preview = asImportPreview(err.data)
      // 数据缺失说明契约被破坏（或中间有代理吞掉了响应体）。这种情况不能
      // 装作导入成功——把原错误抛出去，让界面显示后端给的 message。
      if (preview) return { ok: false, reason: 'has_errors', preview }
    }
    throw err
  }
}

/**
 * 把「未知形状」收敛成 `AssetImportPreview`。
 *
 * `HttpError.data` 的类型是 `unknown`：api 层不认识任何业务形状，也不该认识
 * （否则 client.ts 就得 import 一整棵业务类型树）。但 TS 的断言是单向门，
 * 写成 `err.data as AssetImportPreview` 之后，字段真的缺失也要等到渲染时
 * 才炸。这里显式检查两个界面离不开的数组字段，拿不到就返回 null，
 * 让调用方走「没有明细」的分支，而不是渲染出一张空表并让用户以为
 * 「零错误」。
 */
export function asImportPreview(data: unknown): AssetImportPreview | null {
  if (typeof data !== 'object' || data === null) return null
  const candidate = data as Partial<AssetImportPreview>
  if (!Array.isArray(candidate.errors) || !Array.isArray(candidate.missing_columns)) return null
  return candidate as AssetImportPreview
}

/** 资产状态 → 中文名 */
export const ASSET_STATUS_LABELS: Record<AssetStatus, string> = {
  in_use: '在用',
  idle: '闲置',
  offline: '下线',
  scrapped: '已退役',
}

/** 状态标签配色。退役用 info 而不是 danger：它是资产的正常归宿，不是故障。 */
export const ASSET_STATUS_TAG_TYPE: Record<AssetStatus, 'success' | 'info' | 'warning' | 'danger'> =
  {
    in_use: 'success',
    idle: 'info',
    offline: 'warning',
    scrapped: 'info',
  }

/** 重要性 1–5 的档位名。数字本身没有方向感，标签才让「4 和 5 差在哪」可读。 */
export const IMPORTANCE_LABELS: Record<number, string> = {
  1: '很低',
  2: '较低',
  3: '中等',
  4: '较高',
  5: '很高',
}
