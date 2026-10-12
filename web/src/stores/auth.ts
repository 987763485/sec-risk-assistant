import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import { fetchMe, login as loginApi, logout as logoutApi } from '@/api/auth'
import { clearCsrfToken } from '@/api/http'
import type { Me, PermissionCode, RoleBrief } from '@/api/endpoints'

/**
 * 认证状态。
 *
 * ⚠️ 这里**只**保存「界面需要知道的身份信息」，不保存任何令牌：
 * 令牌走 httpOnly Cookie，由浏览器管理，JS 读不到也就偷不走。
 *
 * 权限判断的唯一依据是后端 `/auth/me` 下发的 `permissions` 数组。
 * 前端不维护「角色 → 权限」映射表——那份真相在后端 rbac.go 里，
 * 前端复制一份的结果一定是两份逐渐失配，最后没人敢改。
 */
export const useAuthStore = defineStore('auth', () => {
  const user = ref<Me | null>(null)
  /** 是否已经尝试过恢复会话（无论成功与否），用于避免重复请求 */
  const resolved = ref(false)

  const isAuthenticated = computed(() => user.value !== null)
  const mustChangePassword = computed(() => user.value?.must_change_password ?? false)
  const roles = computed<RoleBrief[]>(() => user.value?.roles ?? [])
  const displayName = computed(() => user.value?.display_name || user.value?.username || '')
  const permissions = computed<string[]>(() => user.value?.permissions ?? [])

  /**
   * 是否持有某个权限码。
   *
   * 只在「界面是否展示」这个层面使用它。真正的访问控制在后端，
   * 前端隐藏一个菜单只是体验优化，绝不是安全边界。
   */
  function can(code: PermissionCode | string): boolean {
    return permissions.value.includes(code)
  }

  /** 持有任一权限即为真，用于「读或写都能进」的页面 */
  function canAny(...codes: (PermissionCode | string)[]): boolean {
    return codes.some((c) => can(c))
  }

  /** 从后端恢复会话。失败视为未登录，不抛异常。 */
  async function restore(): Promise<boolean> {
    try {
      user.value = await fetchMe()
      return true
    } catch {
      user.value = null
      return false
    } finally {
      resolved.value = true
    }
  }

  async function login(username: string, password: string): Promise<void> {
    await loginApi(username, password)
    // 登录响应只带会话信息，权限码仍需从 /auth/me 取——
    // 这样「登录」与「恢复会话」两条路径得到的是同一份数据形状
    await restore()
  }

  async function logout(): Promise<void> {
    try {
      await logoutApi()
    } finally {
      reset()
    }
  }

  /** 清空本地状态。登出、会话失效、切换账号时都必须调用。 */
  function reset(): void {
    user.value = null
    clearCsrfToken()
    resolved.value = false
  }

  return {
    user,
    resolved,
    isAuthenticated,
    mustChangePassword,
    roles,
    displayName,
    permissions,
    can,
    canAny,
    restore,
    login,
    logout,
    reset,
  }
})
