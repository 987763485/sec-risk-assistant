import type {
  CreateIntegrationRequest,
  FetchVulnIntelRequest,
  FetchVulnIntelResult,
  Integration,
  IntegrationLastStatus,
  IntegrationList,
  IntelSeverity,
  UpdateIntegrationRequest,
} from './endpoints'
import { api } from './http'

/**
 * 情报源集成接口。
 *
 * 权限分工（与后端路由一一对应，见 docs/openapi.yaml 的 integrations 节）：
 *
 * | 动作 | 权限码 | 为什么 |
 * |---|---|---|
 * | 读列表 / 读单条 | `integration:read` | 评估员要在漏洞详情里看到情报 |
 * | 建 / 改配置 | `system:write` | 「配置一个能向外发请求的出站目标」是管理动作 |
 * | 触发拉取 | `integration:write` | 业务动作，不改变系统配置 |
 *
 * 前端**不做**这套判断，只在按钮上按权限显隐（体验层）；
 * 真正的拦阻在后端路由的 `RequirePermission` 上。
 */

/** 集成列表。**不分页**：集成是运维配置，数量以个数计 */
export function listIntegrations(): Promise<IntegrationList> {
  return api.get<IntegrationList>('/integrations')
}

export function getIntegration(id: number): Promise<Integration> {
  return api.get<Integration>(`/integrations/${id}`)
}

export function createIntegration(payload: CreateIntegrationRequest): Promise<Integration> {
  return api.post<Integration>('/integrations', payload)
}

/**
 * 修改集成配置。
 *
 * 未传的字段保持不变，校验按**合并后的最终值**整体进行——
 * 因此「只改类型」也会把地址重新过一遍 SSRF 校验，不会出现
 * 「类型从 local 改成 nvd 但地址还是原来那个内网地址」这种漏网。
 *
 * `credential_env` 是**三态**的：不传 = 不修改；显式 `null` = 清空
 * （不再使用凭据）；传值 = 改为该变量名。想清空时必须显式传 `null`，
 * 传 `''` 会被当作空串凭据名而不是「清空」。
 */
export function updateIntegration(
  id: number,
  payload: UpdateIntegrationRequest,
): Promise<Integration> {
  return api.patch<Integration>(`/integrations/${id}`, payload)
}

/**
 * 触发一次情报拉取。
 *
 * ⚠️ 这个接口**恒定返回 200**，**包括全部失败的情况**。调用方必须读
 * `succeeded` / `failed` / `errors`，不能只看状态码——只回一个 502
 * 会让调用方以为什么都没发生从而重复点击，而成功的那些**已经落库了**。
 *
 * 唯一的非 200 是出站目标被拒（`INTEGRATION_ENDPOINT_BLOCKED`，400）：
 * 那不是「拉取失败」，而是「这个请求根本不该被发出去」。
 *
 * 接口是**幂等**的：同一 `(漏洞, 来源, CVE)` 重复拉取是更新而不是新增，
 * 所以库里的条数不会因为重复点击而膨胀（`inserted` / `updated` 会变）。
 */
export function fetchVulnIntel(
  id: number,
  payload: FetchVulnIntelRequest,
): Promise<FetchVulnIntelResult> {
  return api.post<FetchVulnIntelResult>(`/integrations/${id}/fetch`, payload)
}

// ------------------------------------------------------------------ 展示辅助

/**
 * 最近一次拉取结果的标签。
 *
 * 空串是**合法取值**（从未拉取过），所以不能写成 `success ? '成功' : '失败'`——
 * 那会把「还没试过」渲染成「失败了」。
 */
export const LAST_STATUS_LABELS: Record<string, string> = {
  '': '从未拉取',
  success: '全部成功',
  failed: '存在失败',
}

export const LAST_STATUS_TAG_TYPE: Record<string, 'info' | 'success' | 'warning' | 'danger'> = {
  '': 'info',
  success: 'success',
  failed: 'danger',
}

/** 快照的严重度档位 → 中文 */
export const INTEL_SEVERITY_LABELS: Record<IntelSeverity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  unknown: '未知',
}

/**
 * 快照的严重度档位 → 标签配色。
 *
 * `unknown` 用灰色而不是黄色：它表示「上游既没给档位也没给分数」，
 * 是一个**事实缺失**，把它涂成中危的颜色会让统计看起来有一批中危。
 */
export const INTEL_SEVERITY_TAG_TYPE: Record<
  IntelSeverity,
  'info' | 'success' | 'warning' | 'danger'
> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'success',
  unknown: 'info',
}

/** 最近一次拉取的状态文案；未知状态码原样回显而不是吞掉 */
export function lastStatusLabel(status: IntegrationLastStatus): string {
  return LAST_STATUS_LABELS[status] ?? status
}

export function lastStatusTagType(
  status: IntegrationLastStatus,
): 'info' | 'success' | 'warning' | 'danger' {
  return LAST_STATUS_TAG_TYPE[status] ?? 'info'
}

/**
 * 凭据变量的展示文案。
 *
 * 只回答「有没有」——`credential_present` 是服务进程里该环境变量是否
 * 已设置且非空，**不是**凭据本身。后端也永远不会把凭据发到这里。
 */
export function credentialLabel(row: Integration): string {
  if (!row.credential_env) return '无需凭据'
  return row.credential_present ? '已配置（变量已设置）' : '已登记但变量未设置'
}

/**
 * 拆出漏洞登记的全部 CVE 编号。
 *
 * `cve_ids` 是逗号分隔的**单个字符串**（不是一个数组），且可能为空、
 * 可能有重复、大小写可能不统一。归一化放在这里而不是各调用点各写一次：
 * 漏掉的那处会把 `cve-2021-44228` 送上去，而后端按大写比对，
 * 结果是「明明有这个 CVE 却提示不属于该漏洞」。
 */
export function splitCveIds(raw: string | null | undefined): string[] {
  if (!raw) return []
  const seen = new Set<string>()
  for (const part of raw.split(',')) {
    const id = part.trim().toUpperCase()
    if (id) seen.add(id)
  }
  return [...seen]
}
