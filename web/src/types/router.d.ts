import 'vue-router'

import type { PermissionCode } from '@/api/endpoints'

/**
 * 路由元信息。
 *
 * 用 declare module 扩展而不是在各处 `as string` 强转：
 * 路由元信息是「路由表 ↔ 守卫 ↔ 菜单 ↔ 页面标题」四处共享的契约，
 * 一旦键名写错，类型系统应当立刻报错，而不是在运行时表现为
 * 「菜单不显示」或「标题为空」这类需要翻代码才能定位的问题。
 */
declare module 'vue-router' {
  interface RouteMeta {
    /** 页面标题，用于浏览器标签页与面包屑 */
    title?: string

    /**
     * 是否无需登录即可访问。
     *
     * 必须显式写 true，缺省是「需要登录」——安全侧默认。
     */
    public?: boolean

    /**
     * 访问该路由所需的权限码。
     *
     * 这是前端动态路由与菜单的**唯一**依据：前端不做角色判断，
     * 因为「哪个角色有哪些权限」的真相在后端 rbac.go 里。
     * 前端若自己维护一份角色→权限映射，两份表必然逐渐失配。
     */
    permission?: PermissionCode

    /** 是否出现在左侧菜单中 */
    menu?: boolean

    /** 菜单分组标题，同组的路由会收在同一个折叠面板下 */
    menuGroup?: string

    /** 组内排序，数字小的靠前 */
    menuOrder?: number

    /** 菜单图标（Element Plus 图标组件名） */
    icon?: string

    /**
     * 是否允许「首次登录未改密」的账号访问。
     *
     * 只有改密页与登出需要这个豁免，其余页面对该类账号一律不可达。
     */
    allowMustChangePassword?: boolean

    /** 仅开发环境可见（生产构建会重定向到 404） */
    devOnly?: boolean
  }
}
