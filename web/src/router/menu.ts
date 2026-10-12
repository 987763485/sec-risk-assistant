import type { RouteRecordRaw } from 'vue-router'

import { businessRoutes } from './routes'

/**
 * 由路由表推导左侧菜单。
 *
 * 为什么菜单来自路由表而不是单独维护一份菜单配置：
 * 两份配置意味着「新增页面时改了一处忘了另一处」，表现为页面能访问
 * 但菜单里没有入口——这类缺陷不会报错，只会被用户当成功能没做。
 * 让菜单成为路由表的投影，就从结构上消除了这种可能。
 */
export interface MenuItem {
  /** 路由名，用于 RouterLink 的 :to 与「当前项高亮」判断 */
  name: string
  path: string
  title: string
  icon?: string
  order: number
}

export interface MenuGroup {
  title: string
  items: MenuItem[]
}

export interface MenuTree {
  /** 不属于任何分组的顶级菜单项 */
  topLevel: MenuItem[]
  groups: MenuGroup[]
}

/**
 * 按权限过滤出当前用户可见的菜单。
 *
 * @param can 权限判定函数，通常直接传 authStore.can
 */
export function buildMenuTree(can: (code: string) => boolean): MenuTree {
  const topLevel: MenuItem[] = []
  const groupMap = new Map<string, MenuItem[]>()

  // 递归时把「所在的菜单分组」一路带下去：分组信息写在父级还是子级都能生效，
  // 而且不必为每个菜单项回头再遍历一次路由树
  const walk = (routes: RouteRecordRaw[], inheritedGroup?: string) => {
    for (const route of routes) {
      const meta = route.meta
      const group = meta?.menuGroup ?? inheritedGroup

      if (meta?.menu && !meta.devOnly && route.name) {
        // 权限不足的项直接不收集，而不是先收集再过滤：
        // 这样「越权的菜单项」从不存在于数据结构里，
        // 任何漏判的消费方也不可能把它渲染出来
        const allowed = !meta.permission || can(meta.permission)
        if (allowed) {
          const item: MenuItem = {
            name: String(route.name),
            path: route.path,
            title: meta.title ?? String(route.name),
            icon: meta.icon,
            order: meta.menuOrder ?? 999,
          }
          if (group) {
            const list = groupMap.get(group) ?? []
            list.push(item)
            groupMap.set(group, list)
          } else {
            topLevel.push(item)
          }
        }
      }

      if (route.children?.length) walk(route.children, group)
    }
  }

  walk(businessRoutes)

  const byOrder = (a: MenuItem, b: MenuItem) => a.order - b.order

  const groups: MenuGroup[] = [...groupMap.entries()]
    .map(([title, items]) => ({ title, items: items.sort(byOrder) }))
    .sort((a, b) => (a.items[0]?.order ?? 999) - (b.items[0]?.order ?? 999))

  return { topLevel: topLevel.sort(byOrder), groups }
}
