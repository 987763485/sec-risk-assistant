import { api } from './http'
import type { AuditAction, AuditLogPage } from './endpoints'

/** 审计日志查询参数 */
export interface AuditLogQuery {
  page?: number
  pageSize?: number
  action?: AuditAction | ''
  resource?: string
  user_id?: number
  start_at?: string
  end_at?: string
}

/** 拼 query string，跳过空值。参数用 `object` 的原因见 api/users.ts 同名函数 */
function toQueryString(query: object): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue
    params.set(key, String(value))
  }
  const s = params.toString()
  return s ? `?${s}` : ''
}

/**
 * 审计日志查询。
 *
 * 只有读，没有写与删——「可以被前端删除的审计日志」在合规意义上
 * 等同于没有审计，因此后端也没有开放这两个接口。
 */
export function listAuditLogs(query: AuditLogQuery = {}): Promise<AuditLogPage> {
  return api.get<AuditLogPage>(`/audit-logs${toQueryString(query)}`)
}

/**
 * 审计动作码的中文标签。
 *
 * 放在前端而不是让后端下发：这是纯粹的展示映射，不构成契约的一部分。
 * 后端下发会诱使前端把「后端返回的标签」当成业务判断依据，
 * 而标签文案恰恰是可以随时改的东西。
 */
export const AUDIT_ACTION_LABELS: Record<string, string> = {
  'auth.login': '登录成功',
  'auth.login_failed': '登录失败',
  'auth.logout': '登出',
  'auth.refresh': '刷新会话',
  'auth.token_reuse_detected': '检测到令牌重放',
  'auth.password_change': '修改密码',
  'user.create': '新建用户',
  'user.update': '更新用户',
  'user.disable': '禁用用户',
  'user.enable': '启用用户',
  'user.role_update': '调整角色',
  'user.password_reset': '重置密码',
}

/** 需要高亮显示的高危动作 */
export const AUDIT_DANGER_ACTIONS = new Set([
  'auth.token_reuse_detected',
  'auth.login_failed',
  'user.disable',
  'user.password_reset',
])
