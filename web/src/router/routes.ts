import type { RouteRecordRaw } from 'vue-router'

/**
 * 路由定义。
 *
 * 分两类，这个划分是整套鉴权方案的地基：
 *
 *  - **常量路由**（constantRoutes）：登录、改密、错误页。无需登录或只需
 *    部分登录态即可到达，应用启动时就注册，且永不注销。
 *
 *  - **业务路由**（businessRoutes）：需要权限才能访问的页面。**不随应用启动
 *    注册**，而是在确认登录态之后、按当前用户实际持有的权限码动态挂载
 *    （见 router/index.ts 的守卫）。未登录或权限不足的用户，其路由表中
 *    根本不存在这些记录 —— 手动敲 URL 也只会落到 404。
 *
 * 注意所有业务子路由都写成**绝对路径**：这样菜单构建时无需拼接父子路径，
 * 少一类「多了或少了一个斜杠」的定位成本。vue-router 允许子路由使用绝对
 * 路径，它仍然会渲染在父级 layout 的 RouterView 中。
 */

// ------------------------------------------------------------------ 常量路由

export const constantRoutes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/auth/LoginView.vue'),
    meta: { title: '登录', public: true, allowMustChangePassword: true },
  },
  {
    path: '/change-password',
    name: 'change-password',
    component: () => import('@/views/auth/ChangePasswordView.vue'),
    meta: {
      title: '修改密码',
      // 未改密账号唯一的可达页面，因此必须豁免「必须先改密」这条拦截
      allowMustChangePassword: true,
    },
  },
  {
    path: '/403',
    name: 'forbidden',
    component: () => import('@/views/error/ForbiddenView.vue'),
    meta: { title: '无访问权限' },
  },
  {
    // 开发期专用的样式守门验证页（scripts/verify-style-check.sh 的目标）。
    //
    // 放在**常量路由**而不是业务路由里：业务路由要等登录后才动态挂载，
    // 未登录时路由表里根本没有这一条 —— 无头浏览器拿到的是被守卫重定向的
    // 登录页，断言自然抓不到结果（这正是脚本此前失效的原因）。
    // 该页面不读任何用户数据，免登录访问不影响安全性。
    //
    // 生产环境由守卫的 ⓪ 号分支一律重定向到 404，见 router/index.ts。
    path: '/dev/style-check',
    name: 'style-check',
    component: () => import('@/views/dev/StyleCheckView.vue'),
    meta: { title: '样式守门验证', devOnly: true },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/error/NotFoundView.vue'),
    meta: { title: '页面不存在' },
  },
]

// ------------------------------------------------------------------ 业务路由

export const businessRoutes: RouteRecordRaw[] = [
  {
    path: '/',
    component: () => import('@/layouts/DefaultLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: '/dashboard',
        name: 'dashboard',
        component: () => import('@/views/dashboard/DashboardView.vue'),
        meta: { title: '总览', menu: true, menuOrder: 10, icon: 'Odometer' },
      },
      {
        path: '/system/users',
        name: 'system-users',
        component: () => import('@/views/system/UserListView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/users 需要 user:read
        meta: {
          title: '用户管理',
          permission: 'user:read',
          menu: true,
          menuGroup: '系统管理',
          menuOrder: 20,
          icon: 'User',
        },
      },
      {
        path: '/system/audit-logs',
        name: 'system-audit-logs',
        component: () => import('@/views/system/AuditLogView.vue'),
        meta: {
          title: '审计日志',
          permission: 'audit:read',
          menu: true,
          menuGroup: '系统管理',
          menuOrder: 21,
          icon: 'Document',
        },
      },
      {
        path: '/assets',
        name: 'assets-list',
        component: () => import('@/views/assets/AssetListView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/assets 需要 asset:read
        meta: {
          title: '资产台账',
          permission: 'asset:read',
          menu: true,
          menuGroup: '资产管理',
          menuOrder: 30,
          icon: 'Grid',
        },
      },
      {
        path: '/assets/groups',
        name: 'assets-groups',
        component: () => import('@/views/assets/AssetGroupView.vue'),
        // 资产组没有独立权限码：它决定「资产归谁看」，与资产共用一套
        meta: {
          title: '资产分组',
          permission: 'asset:read',
          menu: true,
          menuGroup: '资产管理',
          menuOrder: 31,
          icon: 'Share',
        },
      },
      {
        path: '/system/dictionaries',
        name: 'system-dictionaries',
        component: () => import('@/views/system/DictionaryView.vue'),
        meta: {
          title: '业务字典',
          permission: 'dictionary:read',
          menu: true,
          menuGroup: '系统管理',
          menuOrder: 22,
          icon: 'Collection',
        },
      },
      {
        path: '/files',
        name: 'files-list',
        component: () => import('@/views/files/FileListView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/files 需要 file:read
        meta: {
          title: '文件管理',
          permission: 'file:read',
          menu: true,
          menuGroup: '漏洞管理',
          menuOrder: 40,
          icon: 'FolderOpened',
        },
      },
      {
        path: '/vulnerabilities',
        name: 'vulnerabilities-list',
        component: () => import('@/views/vulnerabilities/VulnerabilityListView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/vulnerabilities 需要 vulnerability:read
        meta: {
          title: '漏洞清单',
          permission: 'vulnerability:read',
          menu: true,
          menuGroup: '漏洞管理',
          menuOrder: 41,
          icon: 'Warning',
        },
      },
      {
        path: '/assessments',
        name: 'assessments-list',
        component: () => import('@/views/assessments/AssessmentListView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/assessments 需要 assessment:read
        meta: {
          title: '评估任务',
          permission: 'assessment:read',
          menu: true,
          menuGroup: '风险评估',
          menuOrder: 50,
          icon: 'Histogram',
        },
      },
      {
        // 执行页与结果页**不进菜单**（不写 menu）：它们的入口是列表页的行操作。
        // 把「所有评估任务的执行页」塞进侧栏在信息架构上说不通——
        // 菜单里的每一项都应当是一个稳定的入口，而不是「某个具体任务」。
        path: '/assessments/:id',
        name: 'assessment-execute',
        component: () => import('@/views/assessments/AssessmentExecuteView.vue'),
        meta: { title: '评估执行', permission: 'assessment:read' },
      },
      {
        path: '/assessments/:id/result',
        name: 'assessment-result',
        component: () => import('@/views/assessments/AssessmentResultView.vue'),
        meta: { title: '评估结果', permission: 'assessment:read' },
      },
      {
        path: '/remediations',
        name: 'remediations-list',
        component: () => import('@/views/remediations/RemediationListView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/remediations 需要 remediation:read
        meta: {
          title: '整改跟踪',
          permission: 'remediation:read',
          menu: true,
          menuGroup: '整改跟踪',
          menuOrder: 60,
          icon: 'Finished',
        },
      },
      {
        // 详情页不进菜单，理由与评估执行页相同：它是「某一张单子」，
        // 不是一个稳定的入口。入口在列表页与评估结果页的整改状态列。
        path: '/remediations/:id',
        name: 'remediation-detail',
        component: () => import('@/views/remediations/RemediationDetailView.vue'),
        meta: { title: '整改单详情', permission: 'remediation:read' },
      },
      {
        path: '/system/risk-model',
        name: 'system-risk-model',
        component: () => import('@/views/system/RiskModelView.vue'),
        // 读接口对 assessment:read 也放行（评估员要在执行页看阈值），
        // 但**菜单**按 system:read 收口：它属于系统设置，
        // 评估员的入口是执行页里那个只读的阈值面板。
        // 保存按钮另有 system:write 把关。
        meta: {
          title: '风险模型',
          permission: 'system:read',
          menu: true,
          menuGroup: '系统管理',
          menuOrder: 23,
          icon: 'SetUp',
        },
      },
      {
        path: '/system/integrations',
        name: 'system-integrations',
        component: () => import('@/views/system/IntegrationView.vue'),
        // 与后端路由上挂的守卫保持一致：GET /api/integrations 需要 integration:read
        //
        // 菜单按 integration:read 收口，**不是** system:read：评估员与整改员
        // 要在漏洞详情里看到「这条情报来自哪个源」，因此他们需要能进这一页；
        // 而建 / 改配置属于管理动作，按钮另有 system:write 把关
        // （页面里的 canManage），路由本身不为此拦人。
        meta: {
          title: '情报源集成',
          permission: 'integration:read',
          menu: true,
          menuGroup: '系统管理',
          menuOrder: 24,
          icon: 'Connection',
        },
      },
    ],
  },
]
