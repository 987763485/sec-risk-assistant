import { createRouter, createWebHistory } from 'vue-router'

import { useAuthStore } from '@/stores/auth'
import { businessRoutes, constantRoutes } from './routes'

/**
 * 路由与全局守卫。
 *
 * ── 动态路由的核心思路 ──────────────────────────────────────────────
 * 业务路由**不在**应用启动时注册，而是在守卫里确认登录态之后，
 * 按当前用户实际持有的权限码逐条挂载。带来两个性质：
 *
 *   1. 未登录时路由表里不存在任何业务页面，手敲 URL 只会落到 404；
 *   2. 权限不足的页面同样如此，因此「前端忘记隐藏入口」也不会造成访问。
 *
 * 注意这只是**体验层的收口**。真正的访问控制在后端每请求现查权限，
 * 前端隐藏路由永远不能替代服务端校验。
 */
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: constantRoutes,
  scrollBehavior: () => ({ top: 0 }),
})

/** 已动态注册路由的注销函数 */
let dynamicDisposers: (() => void)[] = []

function registerBusinessRoutes(): void {
  if (dynamicDisposers.length > 0) return

  for (const route of businessRoutes) {
    // 只挂载「不需要权限」或「已持有权限」的页面。
    // 这里用的是守卫入口处已经取到的权限码，不额外发请求。
    const children = route.children ?? []
    const allowed = children.filter((child) => {
      const permission = child.meta?.permission
      if (!permission) return true
      return useAuthStore().can(permission)
    })

    if (allowed.length === 0) continue

    dynamicDisposers.push(router.addRoute({ ...route, children: allowed }))
  }
}

/**
 * 注销全部动态路由。
 *
 * 登出与切换账号时必须调用：否则上一个账号挂上去的路由会留在路由表里，
 * 下一个账号虽然访问不到数据（后端仍会拦），但会看到一个不属于自己的菜单。
 */
export function resetRouter(): void {
  dynamicDisposers.forEach((dispose) => dispose())
  dynamicDisposers = []
}

/**
 * 会话失效时的跳转入口。
 *
 * 由 api 层在刷新令牌也救不回来时回调（见 api/http.ts 的 onSessionExpired）。
 * 这里做两件事：清空本地身份、把当前地址塞进 redirect 以便登录后回到原处。
 */
export function redirectToLogin(currentPath: string): void {
  const auth = useAuthStore()
  auth.reset()
  resetRouter()

  if (router.currentRoute.value.name === 'login') return
  void router.replace({
    name: 'login',
    query: currentPath && currentPath !== '/' ? { redirect: currentPath } : undefined,
  })
}

router.beforeEach(async (to) => {
  // ── ⓪ 开发专用页面 ─────────────────────────────────────────────────
  // 必须放在所有分支之前。原先这个检查在 ⑤，而 ① 的 public 分支会先 return，
  // 一旦 dev 页面被标成 public 就绕过了生产环境的 404 —— 顺序即安全性。
  //
  // 开发环境直接放行，且**不要求登录**：它是 verify-style-check.sh 用无头
  // 浏览器访问的自检页，那个浏览器里没有会话；页面本身也不读任何用户数据。
  if (to.meta.devOnly) {
    return import.meta.env.DEV ? true : { name: 'not-found' }
  }

  // ── ① 公开页面直接放行 ─────────────────────────────────────────────
  if (to.meta.public) {
    // 已登录的人再访问登录页没有意义，直接送进主界面
    const auth = useAuthStore()
    if (!auth.resolved) await auth.restore()
    if (auth.isAuthenticated) {
      return auth.mustChangePassword ? { name: 'change-password' } : { path: '/' }
    }
    return true
  }

  const auth = useAuthStore()

  // ── ② 恢复登录态 ───────────────────────────────────────────────────
  // 令牌在 httpOnly Cookie 里，前端无从判断是否已登录，只能问后端。
  // resolved 标记保证整个生命周期里这件事只做一次（登出后会复位）。
  if (!auth.resolved) {
    await auth.restore()
  }

  if (!auth.isAuthenticated) {
    return {
      name: 'login',
      query: to.fullPath && to.fullPath !== '/' ? { redirect: to.fullPath } : undefined,
    }
  }

  // ── ③ 强制改密 ─────────────────────────────────────────────────────
  // 管理员设定的初始密码必须由本人改掉，否则「管理员知道每个人密码」
  // 这件事会一直成立。改密前只放行改密页本身。
  if (auth.mustChangePassword && !to.meta.allowMustChangePassword) {
    return { name: 'change-password' }
  }

  // ── ④ 动态挂载业务路由 ─────────────────────────────────────────────
  // ⚠️ 必须在权限校验之前完成。若放到后面，首屏访问业务页面时会因为
  //    「路由还不存在」而先匹配到通配的 404。
  if (dynamicDisposers.length === 0) {
    registerBusinessRoutes()

    // 路由表变了，当前这次导航是在旧表上解析出来的，结果不可信。
    // 用原目标地址重新导航一次 —— 这里不能简单 return true，
    // 否则用户会停在一个已经过期的匹配结果上（典型表现是刷新后白屏）。
    return { path: to.path, query: to.query, hash: to.hash, replace: true }
  }

  // ── ⑤ 权限校验 ─────────────────────────────────────────────────────
  if (to.meta.permission && !auth.can(to.meta.permission)) {
    return { name: 'forbidden' }
  }

  return true
})

router.afterEach((to) => {
  const title = to.meta.title ?? ''
  document.title = title ? `${title} · 网络安全风险评估助手` : '网络安全风险评估助手'
})

export default router
