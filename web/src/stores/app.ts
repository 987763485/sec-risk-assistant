import { defineStore } from 'pinia'
import { ref } from 'vue'

/**
 * 全局应用状态。
 *
 * 刻意只放非敏感的 UI 状态：当前 P0 阶段只缓存后端健康信息与版本号。
 * 认证令牌走 httpOnly Cookie，**绝不进 Pinia / localStorage**（见 P1）。
 */
export const useAppStore = defineStore('app', () => {
  /** 后端是否可达 */
  const backendOnline = ref<boolean | null>(null)
  /** 后端版本号 */
  const backendVersion = ref<string>('')
  /** 前端构建版本（由 vite define 注入） */
  const frontendVersion = ref<string>(__APP_VERSION__)

  let initialized = false

  function init() {
    if (initialized) return
    initialized = true
    void refreshHealth()
  }

  async function refreshHealth() {
    try {
      const { fetchHealth } = await import('@/api/health')
      const data = await fetchHealth()
      backendOnline.value = data.status === 'ok'
      backendVersion.value = data.version
    } catch {
      backendOnline.value = false
      backendVersion.value = ''
    }
  }

  return {
    backendOnline,
    backendVersion,
    frontendVersion,
    init,
    refreshHealth,
  }
})
