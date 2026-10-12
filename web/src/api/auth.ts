import { api, clearCsrfToken, ensureCsrfToken, setCsrfToken } from './http'
import type { ChangePasswordRequest, Me, Session } from './endpoints'

/**
 * 认证接口。
 *
 * 三条与后端行为强相关的约定，写在这里以免调用方重复踩：
 *
 *  1. **令牌不下发给前端逻辑**。三枚 Cookie 由浏览器自动管理，
 *     这里的函数只负责「发起动作」，不返回、不保存任何令牌。
 *     因此刷新页面后登录态依然成立，而不是像 localStorage 方案那样
 *     需要重新水合。
 *
 *  2. **会话轮换会换掉 CSRF 令牌**。登录与刷新返回的 `csrf_token`
 *     必须写回请求层缓存，否则后续写请求会全部 403。
 *
 *  3. **登出是幂等的**。访问令牌已过期时也能登出成功，调用方无需
 *     先判断有没有登录。
 */

/** 启动时调用一次，确保后续写请求拿得到 CSRF 令牌 */
export function prepareCsrf(): Promise<string> {
  return ensureCsrfToken()
}

/** 登录。成功后会话 Cookie 由后端下发，前端只需更新 CSRF 缓存。 */
export async function login(username: string, password: string): Promise<Session> {
  // 登录前强制取一次新令牌：「停留很久后回来登录」时，
  // 手里那枚可能是上次会话遗留的，与后端 Cookie 不匹配
  await ensureCsrfToken(true)

  const session = await api.post<Session>('/auth/login', { username, password })
  setCsrfToken(session.csrf_token)
  return session
}

/** 登出。无论成功与否都清空本地缓存的 CSRF 令牌。 */
export async function logout(): Promise<void> {
  try {
    await api.post<{ logged_out: boolean }>('/auth/logout')
  } finally {
    clearCsrfToken()
  }
}

/** 读取当前登录者信息（含权限码全集） */
export function fetchMe(): Promise<Me> {
  return api.get<Me>('/auth/me')
}

/** 修改本人密码 */
export function changePassword(payload: ChangePasswordRequest): Promise<{ changed: boolean }> {
  return api.patch<{ changed: boolean }>('/auth/password', payload)
}
