#!/usr/bin/env node
/**
 * 构建产物 CSS 分层静态校验
 * ============================================================================
 * 为什么需要这个脚本：
 *
 * 「Element Plus 样式被压过、Tailwind 工具类失效」这个问题有一个极其难查的
 * 变体 —— 本地开发一切正常，**打包上线后样式全乱**。
 * 根因是构建器的 CSS 合并会拆层、压缩阶段会直接丢弃层顺序声明。
 *
 * 这个脚本对构建产物做静态断言，把它纳入 CI（或 make build 之后的手动检查），
 * 就能在发布前拦住这类问题，而不是等用户反馈「页面错版」。
 *
 * 校验项：
 *   1. 每个 CSS 产物首行都是层顺序声明
 *      异步分包会在任意时机插入 <link>，而层顺序由**先到者**确立，
 *      因此每一个产物都必须自带这份声明，不能只放在入口 chunk 里。
 *   2. 产物中出现的 Element Plus 选择器必须全部位于 `@layer el` 之内
 *   3. 层顺序中 utilities 排在 el 之后（工具类才能覆盖组件样式）
 *   4. 源码里用到的 Element Plus **命令式 API**（ElMessageBox 等）的样式
 *      必须在产物里 —— 它们的样式不会被按需引入自动带上，见 §2.4 的说明
 *
 * ⚠️ 校验项 2 的写法经过一次修正，值得记下来：
 *
 *   初版写的是「每个产物都必须包含 @layer el 块」。它在按路由分包出现之前
 *   一直通过，因为那时每个 chunk 恰好都捎带了 Element Plus 样式。
 *   引入登录页等异步路由后立刻误报 —— 某个 chunk 里 Element Plus 样式被
 *   构建器提升到了共享 chunk，该文件里一个 `.el-` 选择器都没有，
 *   自然不会有 `@layer el` 块。规则把「正常」判成了「错误」。
 *
 *   正确的问法不是「有没有 @layer el」，而是「**有没有漏在层外的** Element Plus
 *   选择器」。新写法直接针对真正要防的失效模式，也不依赖 chunk 的拆分方式。
 *
 * 用法： node scripts/verify-css-layer.mjs
 * ============================================================================
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DIST_ASSETS = join(__dirname, '..', 'dist', 'assets')

/** 期望的层顺序：靠后的层优先级更高 */
const EXPECTED_LAYER_ORDER = ['theme', 'base', 'el', 'components', 'utilities']

const RED = '\u001b[31m'
const GREEN = '\u001b[32m'
const DIM = '\u001b[2m'
const RESET = '\u001b[0m'

function fail(msg) {
  console.error(`${RED}✖${RESET} ${msg}`)
  process.exitCode = 1
}

function ok(msg) {
  console.log(`${GREEN}✔${RESET} ${msg}`)
}

/**
 * 剔除所有 `@layer el { ... }` 块，返回剩余内容。
 *
 * 需要手写括号配对而不是用正则，是因为层块内部可以嵌套（媒体查询、
 * 甚至更深的 @layer），非贪婪正则会在第一个 `}` 处提前收尾，
 * 把本该判为「已进层」的样式误判成「漏在层外」。
 */
function stripLayerElBlocks(css) {
  const marker = /@layer\s+el\s*\{/g
  let result = ''
  let pos = 0
  let match

  while ((match = marker.exec(css)) !== null) {
    if (match.index < pos) continue // 落在上一个已剔除的块内

    result += css.slice(pos, match.index)

    // 从 `{` 开始做括号配对，同时跳过字符串与注释，
    // 避免 content: "}" 或注释里的花括号把配对带偏
    let depth = 0
    let i = match.index + match[0].length - 1
    for (; i < css.length; i++) {
      const ch = css[i]
      if (ch === '"' || ch === "'") {
        const quote = ch
        i++
        while (i < css.length && css[i] !== quote) {
          if (css[i] === '\\') i++
          i++
        }
      } else if (ch === '/' && css[i + 1] === '*') {
        const end = css.indexOf('*/', i + 2)
        i = end === -1 ? css.length : end + 1
      } else if (ch === '{') {
        depth++
      } else if (ch === '}') {
        depth--
        if (depth === 0) {
          i++
          break
        }
      }
    }

    pos = i
    marker.lastIndex = i
  }

  result += css.slice(pos)
  return result
}

/**
 * 找出「漏在 @layer el 之外」的 Element Plus 选择器，返回若干示例片段。
 *
 * 判据是 `.el-` 类选择器，而不是 `--el-` CSS 变量：
 * 业务代码经常以 `var(--el-text-color-primary, #303133)` 的形式复用 EP 的设计
 * 变量（本项目的 base 层就是这么写的），那属于正常用法，
 * 不该被判成「EP 样式漏在层外」。
 */
function findUnlayeredElementPlusRules(css) {
  const outside = stripLayerElBlocks(css)
  const samples = []
  const re = /[^{}]{0,60}\.el-[^{}]{0,60}\{[^{}]{0,80}/g

  let m
  while ((m = re.exec(outside)) !== null) {
    samples.push(m[0].replace(/\s+/g, ' ').trim())
    if (samples.length >= 3) break
  }
  return samples
}

const SRC_DIR = join(__dirname, '..', 'src')

/**
 * Element Plus 的**命令式 API**（函数调用式）及其样式入口。
 *
 * 这些标识符的样式不会被按需引入自动带上 —— resolver 只解析模板标签 ——
 * 必须在 `src/main.ts` 里显式 import 对应的 style 入口（见 docs/08 §2.4）。
 *
 * marker 的选法有讲究：必须是**只可能由该组件的 CSS 产生**的类名，
 * 且不能是另一个 marker 的前缀。反例：用 `.el-message` 作 marker 时，
 * `.el-message-box` 的产物字符串会把它一并命中 ——
 * 「message 样式丢失」于是被判成通过，而它正是最该被抓住的那一种。
 */
const IMPERATIVE_APIS = {
  ElMessage: {
    style: 'element-plus/es/components/message/style/css',
    marker: '.el-message__content',
  },
  ElMessageBox: {
    style: 'element-plus/es/components/message-box/style/css',
    marker: '.el-message-box__content',
  },
  ElNotification: {
    style: 'element-plus/es/components/notification/style/css',
    marker: '.el-notification__content',
  },
  ElLoading: {
    style: 'element-plus/es/components/loading/style/css',
    marker: '.el-loading-mask',
  },
}

/** 递归收集 src 下的 .ts / .vue 文件 */
function walkSourceFiles(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walkSourceFiles(full, out)
    else if (/\.(ts|vue)$/.test(entry.name)) out.push(full)
  }
  return out
}

/**
 * 收集源码里从 `'element-plus'` 具名导入的标识符。
 *
 * 之所以要**从源码推导**而不是写死一份清单：将来有人开始用 `ElNotification`，
 * 写死清单的校验器不会有任何反应，于是同一个坑会再踩一次。
 * 从实际用法推导，则「用了但没引样式」会在构建期立刻失败。
 */
function collectElementPlusImports() {
  const used = new Set()
  const importRe = /import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*['"]element-plus['"]/g

  for (const file of walkSourceFiles(SRC_DIR)) {
    const text = readFileSync(file, 'utf8')
    let m
    while ((m = importRe.exec(text)) !== null) {
      for (const raw of m[1].split(',')) {
        const name = raw
          .trim()
          .replace(/^type\s+/, '')
          .split(/\s+as\s+/)[0]
          .trim()
        if (name) used.add(name)
      }
    }
  }
  return used
}

function main() {
  if (!existsSync(DIST_ASSETS)) {
    fail(`未找到构建产物目录：${DIST_ASSETS}\n  请先执行 npm run build`)
    return
  }

  const cssFiles = readdirSync(DIST_ASSETS).filter((f) => f.endsWith('.css'))

  if (cssFiles.length === 0) {
    fail('构建产物中没有任何 CSS 文件，构建可能未成功完成')
    return
  }

  console.log(`\n${DIM}校验 ${cssFiles.length} 个 CSS 产物…${RESET}\n`)

  const expectedStatement = `@layer ${EXPECTED_LAYER_ORDER.join(', ')};`

  for (const file of cssFiles) {
    const content = readFileSync(join(DIST_ASSETS, file), 'utf8')

    // ── ① 首行必须是层顺序声明
    if (!content.startsWith(expectedStatement)) {
      const actual = content.slice(0, 120).split('\n')[0]
      fail(`${file}：首行不是层顺序声明\n    期望：${expectedStatement}\n    实际：${actual}`)
      continue
    }

    // ── ② Element Plus 选择器不得漏在 @layer el 之外
    //    注意：这条**不要求**每个产物都含 @layer el —— 按路由分包后，
    //    只带业务样式、不含 EP 样式的 chunk 是正常且常见的。
    //    要防的是「EP 样式进了产物却没被包进层」。
    const unlayered = findUnlayeredElementPlusRules(content)
    if (unlayered.length > 0) {
      fail(
        `${file}：发现 ${unlayered.length} 处 Element Plus 样式未进 @layer el，` +
          `会被 Tailwind 工具类反向压制\n    例如：${unlayered[0]}`,
      )
      continue
    }

    // ── ③ 层顺序中 utilities 必须在 el 之后
    const orderMatch = content.match(/^@layer ([^;]+);/)
    const layers = orderMatch ? orderMatch[1].split(',').map((s) => s.trim()) : []
    const elIndex = layers.indexOf('el')
    const utilIndex = layers.indexOf('utilities')
    if (elIndex === -1 || utilIndex === -1 || utilIndex < elIndex) {
      fail(`${file}：层顺序有误，utilities 必须排在 el 之后（当前：${layers.join(', ')}）`)
      continue
    }

    console.log(
      `${GREEN}✔${RESET} ${file.padEnd(38)} ${DIM}${(content.length / 1024).toFixed(1)} KB${RESET}`,
    )
  }

  // ── ④ 命令式 API 的样式必须在产物里（见 docs/08 §2.4）
  //    这类样式的缺失不会报错、不会告警，只是弹层拿到一堆没有 CSS 的类名。
  //    素材是「源码里真的 import 了哪些标识符」，所以将来新增一个命令式 API
  //    却忘了引样式时，这里会直接失败，而不是再静默一次。
  const allCss = cssFiles.map((f) => readFileSync(join(DIST_ASSETS, f), 'utf8')).join('\n')
  const usedApis = collectElementPlusImports()

  for (const [name, { style, marker }] of Object.entries(IMPERATIVE_APIS)) {
    if (!usedApis.has(name)) continue
    if (allCss.includes(marker)) continue

    fail(
      `${name} 的样式不在产物中（找不到 \`${marker}\`）\n` +
        `    ${name} 是命令式调用，按需引入不会带上它的样式。\n` +
        `    修法：在 web/src/main.ts 增加一行   import '${style}'\n` +
        `    详见 docs/08-前端样式规范.md §2.4`,
    )
  }

  console.log('')

  if (process.exitCode) {
    console.error(`${RED}CSS 分层校验未通过 —— 上线后会出现样式错乱，请勿发布。${RESET}\n`)
    return
  }

  ok(`全部 ${cssFiles.length} 个 CSS 产物均通过：层顺序正确，Element Plus 已进 @layer el`)
  ok(
    `命令式 API 样式齐全（已 import：${[...usedApis].filter((n) => n in IMPERATIVE_APIS).join(' / ') || '无'}）`,
  )
  console.log(`${DIM}  层优先级（低 → 高）：${EXPECTED_LAYER_ORDER.join(' → ')}${RESET}\n`)
}

main()
