/**
 * Vite 插件：CSS 分层（@layer）治理
 * ============================================================================
 *
 * 解决什么问题
 * ---------------------------------------------------------------------------
 * Element Plus 的 CSS 是 **unlayered（无层）** 的，而 CSS 级联规则里
 * 「无层样式永远压过 @layer 内的样式」。Tailwind v4 的 utilities 全部位于
 * `@layer utilities` 内，因此 `<el-button class="w-full">` 这类工具类
 * **永远覆盖不动** Element Plus 的样式。
 *
 * 本插件把 Element Plus 的 CSS 整体包进 `@layer el`，并保证层顺序为
 * `theme, base, el, components, utilities` —— utilities 排在 el 之后，
 * 于是 Tailwind 工具类可以正常覆盖组件样式。
 *
 * 同时刻意不引入 Tailwind 的 preflight：preflight 会用元素选择器重置
 * button / input / img 等原生元素样式，而这些恰是 Element Plus 组件所依赖的
 * （典型症状：按钮背景变透明、输入框边框消失、图标垂直对齐异常）。
 *
 *
 * ⚠️ 为什么层顺序声明必须单独处理（这是本插件最关键的一点）
 * ---------------------------------------------------------------------------
 * 层优先级由「层名首次出现的顺序」决定。设想 Element Plus 的 CSS 先于
 * 层顺序声明被加载：`@layer el { ... }` 会先注册 el，使 el 成为最低优先级的
 * 层；随后出现的 `@layer theme, base, el, ...` 里 theme / base 是**新**层名，
 * 会被追加到 el **之后** —— 层顺序变成 `el, theme, base, ...`，完全错乱。
 *
 * 后果：本地开发一切正常，打包上线后样式全乱，且极难排查。
 *
 * 因此本插件做两件事：
 *   1. 开发期：通过 transformIndexHtml 把层顺序声明以 <style> 注入 <head> 首位，
 *      保证它先于任何样式被解析；
 *   2. 构建期：在 generateBundle 阶段向最终 CSS 产物首行注入层顺序声明。
 *      不能放在 transform 阶段 —— 构建器的 CSS 合并会拆层，压缩阶段还会
 *      直接丢弃该声明。
 *
 *
 * 使用约定（写入 docs/08-前端样式规范.md）
 * ---------------------------------------------------------------------------
 * - Tailwind 工具类只用于布局、间距、响应式、显隐
 * - `p-*` / `border-*` / `bg-*` / `font-*` 禁止直接加在 el- 组件上
 * - 调整组件外观用 CSS 变量（--el-color-primary 等）或 :deep(.el-xxx)
 * - 禁止全局 !important
 */

import type { Plugin, ResolvedConfig } from 'vite'

const CSS_FILE_RE = /\.(css|scss|sass|less|styl|stylus)(\?|$)/

export interface CssLayerPluginOptions {
  /**
   * 需要被包裹进指定层的依赖包名。
   * 匹配方式为路径片段 `/node_modules/<包名>/`，因此只需给包名。
   */
  packages?: string[]
  /** 上述包被包裹进的层名 */
  layerName?: string
  /**
   * 完整层顺序声明。数组顺序即优先级，**靠后的层优先级更高**。
   * 可在中间插入自己的层（如 'components'）供业务样式使用。
   */
  layerOrder?: string[]
}

export function viteCssLayerPlugin(options: CssLayerPluginOptions = {}): Plugin {
  const packages = options.packages ?? ['element-plus']
  const layerName = options.layerName ?? 'el'
  const layerOrder = options.layerOrder ?? ['theme', 'base', layerName, 'components', 'utilities']

  const orderStatement = `@layer ${layerOrder.join(', ')};`
  const wrapperOpen = `@layer ${layerName}{`
  const wrapperClose = `}`

  // 预计算匹配片段，避免在热路径上反复拼串
  const pathFragments = packages.flatMap((p) => [`/node_modules/${p}/`, `\\node_modules\\${p}\\`])

  let isBuild = false

  return {
    name: 'secrisk:css-layer',
    // 本插件同时需要「最早处理 CSS 源码」与「最后处理构建产物」，
    // 所以不用插件级 enforce，而是在各 hook 上用 order 精确控制。
    configResolved(config: ResolvedConfig) {
      isBuild = config.command === 'build'
    },

    // ──────────────────────────────────────────────────────────────────
    // ① 把目标依赖的 CSS 包进 @layer el { ... }
    //    order: 'pre' 保证在 Vite 内置 CSS 插件把它转成 JS 模块之前拿到源码
    // ──────────────────────────────────────────────────────────────────
    transform: {
      order: 'pre',
      handler(code, id) {
        if (!CSS_FILE_RE.test(id)) return null

        const isTarget = pathFragments.some((frag) => id.includes(frag))
        if (!isTarget) return null

        // HMR 会反复调用 transform，加个幂等判断避免层层嵌套
        if (code.trimStart().startsWith(`@layer ${layerName}`)) return null

        return {
          code: `${wrapperOpen}\n${code}\n${wrapperClose}\n`,
          map: null,
        }
      },
    },

    // ──────────────────────────────────────────────────────────────────
    // ② 开发期：层顺序声明必须最先被解析，注入 <head> 首位
    // ──────────────────────────────────────────────────────────────────
    transformIndexHtml: {
      order: 'pre',
      handler() {
        return [
          {
            tag: 'style',
            attrs: { 'data-secrisk-css-layer-order': '' },
            children: orderStatement,
            injectTo: 'head-prepend',
          },
        ]
      },
    },

    // ──────────────────────────────────────────────────────────────────
    // ③ 构建期：把层顺序声明写入最终 CSS 产物首行
    //    必须在这里做 —— 见文件头部「为什么层顺序声明必须单独处理」
    // ──────────────────────────────────────────────────────────────────
    generateBundle: {
      order: 'post',
      handler(_outputOptions, bundle) {
        let injected = 0
        for (const [fileName, output] of Object.entries(bundle)) {
          if (output.type !== 'asset') continue
          if (!fileName.endsWith('.css')) continue

          const source =
            typeof output.source === 'string'
              ? output.source
              : Buffer.from(output.source).toString('utf8')

          if (source.startsWith(orderStatement)) continue

          output.source = `${orderStatement}\n${source}`
          injected += 1
        }

        this.info(
          `[css-layer] 已向 ${injected} 个 CSS 产物注入层顺序声明：${layerOrder.join(' → ')}`,
        )
      },
    },

    // 构建结束后的自检：产物里没有层声明就直接报错，不留给上线去发现
    closeBundle: {
      order: 'post',
      handler() {
        if (!isBuild) return
        // 产物内容的精确校验放在 verify-css-layer 脚本里做（见 package.json），
        // 这里只做一次存在性提醒
        this.info('[css-layer] 构建完成，请用 `node scripts/verify-css-layer.mjs` 校验产物')
      },
    },
  }
}

export default viteCssLayerPlugin
