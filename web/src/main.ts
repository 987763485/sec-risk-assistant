import { createApp } from 'vue'
import { createPinia } from 'pinia'

import App from './App.vue'
import router, { redirectToLogin } from './router'
import { onSessionExpired } from './api/http'

// ⚠️ 样式入口必须在最前，它定义了 CSS 层顺序（详见文件内注释）
import './styles/index.css'

/**
 * Element Plus **命令式 API** 的样式必须在这里显式引入 —— 少一行就是一个静默的样式故障。
 *
 * 按需引入（unplugin-vue-components + ElementPlusResolver）只解析**模板里的标签**：
 * 写 `<el-dialog>` 会顺带把 el-dialog 的样式带进来。而
 * `ElMessageBox.confirm(...)` / `ElMessage.success(...)` 是**函数调用**，
 * 走的是 `import { ElMessage } from 'element-plus'` 这条普通导入路径 ——
 * resolver 不介入，样式也就从来没有被生成过。
 *
 * 症状（实测）：退出登录的确认框只有一层灰色遮罩（`.el-overlay` 恰好被
 * `el-dialog` 顺带引入），弹层本体与按钮是**完全没有 CSS 的裸 DOM**；
 * `ElMessage` 的轻提示同理。它既不报错也不告警，只能靠肉眼发现。
 *
 * 这两条路径都落在 node_modules/element-plus 下，因此会被
 * `plugins/vite-plugin-css-layer.ts` 一并包进 `@layer el`，与其它组件样式同层、
 * 同样受 Tailwind 工具类覆盖（见 docs/08-前端样式规范.md §2.4）。
 *
 * ⚠️ 删掉任何一行，`npm run verify:css` 的第 ④ 项断言会失败
 *    （见 web/scripts/verify-css-layer.mjs），不会静默退化。
 */
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'

const app = createApp(App)

app.use(createPinia())
app.use(router)

/**
 * 把「会话彻底失效」接到路由上。
 *
 * api 层在「刷新令牌也救不回来」时回调这里。用回调注册而不是在 api 层
 * 直接 import router，是为了避免 api → router → store → api 的循环依赖
 * （见 api/http.ts 中 onSessionExpired 的说明）。
 */
onSessionExpired(() => {
  redirectToLogin(router.currentRoute.value.fullPath)
})

// 全局错误兜底：避免组件内未捕获异常导致整页白屏且无任何提示
app.config.errorHandler = (err, _instance, info) => {
  console.error('[全局异常]', err, info)
}

app.mount('#app')
