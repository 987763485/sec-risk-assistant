<script setup lang="ts">
/**
 * ⚠️ P0 守门验证页（开发期专用，生产构建由路由守卫屏蔽）
 * ============================================================================
 * 用**运行时断言**代替肉眼看：直接读取 getComputedStyle / getBoundingClientRect
 * 的真实计算结果，客观判定 Element Plus × Tailwind 的共存方案是否成立。
 *
 * 通过标准（对应实现计划 2.5 节）：
 *   ① el-button / el-input / el-icon 渲染正常（未被 preflight 破坏）
 *   ② <el-button class="w-full"> 工具类确实生效 → 证明分层优先级正确
 *   ③ <div class="flex gap-4"> 等纯布局类正常生效
 *   ④ 命令式 API 的样式确实到达了浏览器（见下方说明）
 *
 * ── ④ 为什么必须单独断言，且必须用真的弹层 ──────────────────────────
 * 按需引入只解析**模板标签**。`ElMessageBox.confirm()` 是函数调用，
 * 它的样式要靠 main.ts 里显式 import 才进得来；漏掉时既不报错也不告警，
 * 只是弹层拿到一堆没有 CSS 的类名（实测症状：退出登录的确认框只剩一层灰遮罩）。
 *
 * 因此这一项**不能**用模板里的 <el-dialog> 代替 —— 模板组件正常恰恰说明不了
 * 命令式 API 正常，两者走的是两条不同的样式引入路径。必须真的弹一个出来，
 * 量它的计算样式。
 *
 * ── 三条断言设计上的坑（踩过才知道）────────────────────────────────
 * 1. Element Plus 的 ElInput 把 $attrs 透传到**内层 <input>** 而不是根节点，
 *    所以 `data-check` 挂不到 .el-input 上。必须用外层容器做锚点。
 * 2. 「svg 的 display 是不是 block」**不能**用来判断 preflight：
 *    svg 是 .el-icon（display: inline-flex）的 flex item，
 *    其 inline 会被 CSS 规范块化成 block —— Element Plus 的图标永远是 block。
 * 3. 真正能直接检出 preflight 的判据是**原生标题元素**：
 *    preflight 把所有 h1~h6 重置为 `font-size: inherit; font-weight: inherit`，
 *    所以只要量一下未被任何类修饰的 h1 字号，就能确定 preflight 是否生效。
 */
import { computed, nextTick, onMounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'

type Status = 'pass' | 'fail'

interface CheckResult {
  id: string
  title: string
  expected: string
  actual: string
  status: Status
  /** 不通过时的排查方向 */
  hint: string
}

const TRANSPARENT = new Set(['rgba(0, 0, 0, 0)', 'transparent', ''])

const root = ref<HTMLElement | null>(null)
const results = ref<CheckResult[]>([])
const running = ref(false)
const inputValue = ref('')

const passedCount = computed(() => results.value.filter((r) => r.status === 'pass').length)
const totalCount = computed(() => results.value.length)
const allPassed = computed(() => totalCount.value > 0 && passedCount.value === totalCount.value)

/**
 * 机器可读的结果快照。
 *
 * 供无头浏览器（scripts/verify-style-check.sh）提取后做自动断言 ——
 * 这样「样式共存是否成立」就能进 CI，而不是靠人肉看页面。
 */
const reportJson = computed(() =>
  JSON.stringify(
    {
      passed: passedCount.value,
      total: totalCount.value,
      allPassed: allPassed.value,
      checks: results.value.map((r) => ({
        id: r.id,
        title: r.title,
        status: r.status,
        actual: r.actual,
      })),
    },
    null,
    2,
  ),
)

/** 读取元素计算样式；元素不存在时抛出明确错误，避免断言静默「通过」 */
function styleOf(sel: string): CSSStyleDeclaration {
  const el = root.value?.querySelector<HTMLElement>(sel)
  if (!el) throw new Error(`断言元素未找到: ${sel}`)
  return getComputedStyle(el)
}

function rectOf(sel: string, index = 0): DOMRect {
  const list = root.value?.querySelectorAll<HTMLElement>(sel)
  const el = list?.[index]
  if (!el) throw new Error(`断言元素未找到: ${sel}[${index}]`)
  return el.getBoundingClientRect()
}

function parentRectOf(sel: string): DOMRect {
  const el = root.value?.querySelector<HTMLElement>(sel)
  if (!el?.parentElement) throw new Error(`断言元素的父节点未找到: ${sel}`)
  return el.parentElement.getBoundingClientRect()
}

/** 查找层顺序声明：优先看注入的 <style>，否则扫描样式表首条规则 */
function findLayerOrder(): string | null {
  const tag = document.querySelector<HTMLStyleElement>('style[data-secrisk-css-layer-order]')
  if (tag?.textContent) return tag.textContent.trim()

  for (const sheet of Array.from(document.styleSheets)) {
    try {
      const first: CSSRule | undefined = sheet.cssRules?.[0]
      if (first && String(first.cssText).trimStart().startsWith('@layer')) {
        return String(first.cssText).trim()
      }
    } catch {
      // 跨域样式表读取 cssRules 会抛错，跳过
    }
  }
  return null
}

/**
 * ④ 真的弹一个 ElMessageBox 出来，量它的计算样式。
 *
 * 断言的是「样式有没有到浏览器」，而不是「类名有没有生成」——
 * 缺样式时类名一个不少，只有计算样式是空的。
 *
 * 两个刻意的选择：
 *   - 用 offsetWidth / offsetHeight 而不是 getBoundingClientRect()：
 *     后者返回**变换后**的尺寸，弹出动画（scale）进行中会让宽度读数偏小，
 *     产生随机失败。offset* 是布局尺寸，不受 transform 影响。
 *   - 无论成败都在 finally 里 ElMessageBox.close()：它挂在 <body> 上，
 *     不收起会留一层遮罩盖住页面，后续断言（以及截图）都会跟着失真。
 */
async function checkMessageBoxStyle(): Promise<CheckResult> {
  const id = 'imperative-style'
  const title = '④ 命令式 API（ElMessageBox）样式已生效'
  const expected = '.el-message-box 背景不透明，且布局尺寸 ≥ 200×50px'
  const hint =
    'Element Plus 命令式 API 的样式未被引入 —— 在 web/src/main.ts 补 ' +
    "import 'element-plus/es/components/message-box/style/css'（见 docs/08 §2.4）"

  // 先清掉可能还挂着的上一个实例。ElMessageBox 内部**没有队列**：
  // 每调一次 confirm() 就新挂一个 `<div class="el-message-box">` 到 <body>，
  // 而 `MessageBox.close()` 是 forEach 关掉**全部**实例。
  // 不清的话，「重新检测」连点两次会让 querySelector 选到上一个个旧弹层 ——
  // 断言恰好仍然通过（旧弹层也有样式），但测的已经不是这一次挂上去的那个了。
  ElMessageBox.close()

  // 不 await：confirm() 的 Promise 要等用户操作才 settle，
  // 而这里只需要弹层出现在 DOM 里。先挂一个 catch，避免 UnhandledRejection。
  void ElMessageBox.confirm('样式自检用的临时弹层，无需操作', '样式自检', {
    type: 'warning',
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    showClose: false,
  }).catch(() => {})

  try {
    // 与 runChecks 同一条理由：用定时器而不是 rAF —— 无头浏览器会节流 rAF
    await new Promise<void>((resolve) => setTimeout(resolve, 200))

    // 取**最后一个**：正在淡出的旧弹层在过渡结束前仍留在 DOM 里，
    // querySelector 会先命中它。new 挂上去的那个一定排在后面。
    const boxes = document.querySelectorAll<HTMLElement>('.el-message-box')
    const box = boxes[boxes.length - 1]
    if (!box) {
      return {
        id,
        title,
        expected,
        actual: '未在 DOM 中找到 .el-message-box（弹层未渲染）',
        status: 'fail',
        hint,
      }
    }

    const bg = getComputedStyle(box).backgroundColor
    const w = box.offsetWidth
    const h = box.offsetHeight
    const ok = !TRANSPARENT.has(bg) && w >= 200 && h >= 50

    return {
      id,
      title,
      expected,
      actual: `background=${bg}，size=${w}×${h}px`,
      status: ok ? 'pass' : 'fail',
      hint,
    }
  } catch (err) {
    return { id, title, expected, actual: String(err), status: 'fail', hint }
  } finally {
    ElMessageBox.close()
  }
}

async function runChecks() {
  running.value = true
  await nextTick()

  // ⚠️ 刻意用 setTimeout 而不是 requestAnimationFrame 等布局稳定：
  //    无头浏览器（以及被切到后台的标签页）会节流甚至完全不触发 rAF，
  //    那样断言会永远卡在等待里 —— 表现为「页面正常但结果为空」，极难排查。
  //    定时器不受此影响，且虚拟时间会可靠地推进它。
  await new Promise<void>((resolve) => setTimeout(resolve, 200))

  const list: CheckResult[] = []
  const add = (
    id: string,
    title: string,
    expected: string,
    actual: string,
    ok: boolean,
    hint: string,
  ) => {
    list.push({ id, title, expected, actual, status: ok ? 'pass' : 'fail', hint })
  }

  const guard = (id: string, title: string, hint: string, fn: () => void) => {
    try {
      fn()
    } catch (err) {
      add(id, title, '—', String(err), false, hint)
    }
  }

  // ── ① 组件渲染正常（preflight 未破坏原生元素默认样式）──────────────
  guard('btn-bg', '① el-button 背景不透明', 'preflight 未关闭，重置了原生 button 样式', () => {
    const s = styleOf('[data-check="btn"]')
    const bgOk = !TRANSPARENT.has(s.backgroundColor)
    const paddingOk = Number.parseFloat(s.paddingLeft) >= 8
    add(
      'btn-bg',
      '① el-button 背景不透明',
      '背景色 ≠ 透明，且左右内边距 ≥ 8px',
      `background=${s.backgroundColor}，paddingLeft=${s.paddingLeft}`,
      bgOk && paddingOk,
      'preflight 未关闭，重置了原生 button 样式',
    )
  })

  // 直接检出 preflight 是否生效。
  // preflight 会把 h1~h6 重置为 font-size: inherit / font-weight: inherit，
  // 而未受影响的 h1 会保持浏览器默认的 2em（body 14px → 28px）。
  guard(
    'preflight-off',
    '① Tailwind preflight 确认已关闭',
    'preflight 未关闭 —— 它会重置 Element Plus 依赖的 button / input / img 默认样式',
    () => {
      const s = styleOf('[data-check="raw-h1"]')
      const bodySize = Number.parseFloat(styleOf('[data-check="raw-h1"]').fontSize)
      const sizeOk = bodySize >= 24
      const weightOk = Number.parseInt(s.fontWeight, 10) >= 700
      add(
        'preflight-off',
        '① Tailwind preflight 确认已关闭',
        '原生 h1 字号 ≥ 24px 且加粗（未被重置为继承）',
        `font-size=${s.fontSize}，font-weight=${s.fontWeight}`,
        sizeOk && weightOk,
        'preflight 未关闭 —— 它会重置 Element Plus 依赖的 button / input / img 默认样式',
      )
    },
  )

  guard('input-border', '① el-input 边框正常', 'preflight 未关闭，重置了 input 的边框', () => {
    // ⚠️ 锚点用外层容器：ElInput 会把 $attrs 透传到内层 <input>，
    //    data-check 挂不到根 .el-input 上
    const s = styleOf('[data-check="input-box"] .el-input__wrapper')
    const shadowOk = s.boxShadow !== 'none' && s.boxShadow !== ''
    const borderOk = s.borderStyle !== 'none' && Number.parseFloat(s.borderWidth) > 0
    add(
      'input-border',
      '① el-input 边框正常',
      'box-shadow 或 border 至少其一可见',
      `box-shadow=${s.boxShadow}，border=${s.borderWidth} ${s.borderStyle}`,
      shadowOk || borderOk,
      'preflight 未关闭，重置了 input 的边框',
    )
  })

  guard('icon-inline', '① el-icon 行内布局正常', '图标被撑成块级元素，把行高撑开', () => {
    const pStyle = styleOf('[data-check="inline-text"]')
    const pRect = rectOf('[data-check="inline-text"]')
    const iconRect = rectOf('[data-check="inline-text"] .el-icon')
    const svgRect = rectOf('[data-check="inline-text"] svg')

    const expectedLineHeight = Number.parseFloat(pStyle.lineHeight)
    // 图标若被撑成独立一块，段落会变成两行高
    const singleLine = pRect.height <= expectedLineHeight * 1.4
    // 图标应落在这一行的高度范围内，而不是溢出行框
    const inlineOk = iconRect.top >= pRect.top - 1 && iconRect.bottom <= pRect.bottom + 1
    const square = Math.abs(svgRect.width - svgRect.height) < 1.5 && svgRect.width > 0

    add(
      'icon-inline',
      '① el-icon 行内布局正常',
      '段落保持单行，图标完整落在行框内且为正方形',
      `段落高=${pRect.height.toFixed(1)}px，行高=${expectedLineHeight}px，svg=${svgRect.width.toFixed(1)}×${svgRect.height.toFixed(1)}px`,
      singleLine && inlineOk && square,
      '图标被撑成块级元素，把行高撑开',
    )
  })

  guard('icon-align', '① el-icon 垂直居中', 'preflight 破坏了 svg 的尺寸或对齐', () => {
    const iconRect = rectOf('[data-check="icon"]')
    const svgRect = rectOf('[data-check="icon"] svg')

    // svg 应当铺满 1em 的图标盒子（正方形）
    const square = Math.abs(svgRect.width - svgRect.height) < 1.5 && svgRect.width > 0
    // 应在图标盒子里垂直居中
    const topGap = svgRect.top - iconRect.top
    const bottomGap = iconRect.bottom - svgRect.bottom
    const centered = Math.abs(topGap - bottomGap) < 1.5

    add(
      'icon-align',
      '① el-icon 垂直居中',
      'svg 正方形，且在图标盒子内上下居中（误差 < 1.5px）',
      `svg=${svgRect.width.toFixed(1)}×${svgRect.height.toFixed(1)}px，上间隙=${topGap.toFixed(1)}px，下间隙=${bottomGap.toFixed(1)}px`,
      square && centered,
      'preflight 破坏了 svg 的尺寸或对齐',
    )
  })

  // ── ② 分层优先级：工具类必须能覆盖组件样式 ──────────────────────────
  guard(
    'w-full',
    '② el-button class="w-full" 生效',
    'Element Plus 样式未进 @layer el，无层样式压过了 @layer utilities',
    () => {
      const btn = rectOf('[data-check="full-btn"]')
      const parent = parentRectOf('[data-check="full-btn"]')
      const diff = Math.abs(btn.width - parent.width)
      add(
        'w-full',
        '② el-button class="w-full" 生效',
        '按钮宽度 = 父容器内容宽度（误差 < 2px）',
        `按钮=${btn.width.toFixed(1)}px，父容器=${parent.width.toFixed(1)}px，差=${diff.toFixed(1)}px`,
        diff < 2,
        'Element Plus 样式未进 @layer el，无层样式压过了 @layer utilities',
      )
    },
  )

  // ── ③ 纯布局类正常 ────────────────────────────────────────────────
  guard('flex-gap', '③ flex / gap 布局类生效', 'Tailwind utilities 未被引入或层顺序有误', () => {
    const s = styleOf('[data-check="flex"]')
    const gapOk = Number.parseFloat(s.columnGap) === 16 // gap-4 = 1rem
    add(
      'flex-gap',
      '③ flex / gap 布局类生效',
      'display=flex，column-gap=16px',
      `display=${s.display}，column-gap=${s.columnGap}`,
      s.display === 'flex' && gapOk,
      'Tailwind utilities 未被引入或层顺序有误',
    )
  })

  guard('tailwind-pad', '③ Tailwind 间距类生效', '@import tailwindcss/utilities.css 未生效', () => {
    const s = styleOf('[data-check="pad"]')
    const padOk = Number.parseFloat(s.paddingTop) === 16 // p-4 = 1rem
    add(
      'tailwind-pad',
      '③ Tailwind 间距类生效',
      'padding-top=16px（p-4）',
      `padding-top=${s.paddingTop}`,
      padOk,
      '@import tailwindcss/utilities.css 未生效',
    )
  })

  // ── 附加：层顺序声明是否存在（打包后失效是最难排查的坑）─────────────
  const layerOrder = findLayerOrder()
  add(
    'layer-order',
    '附加 层顺序声明已注入',
    '存在以 @layer theme, base, el, ... 开头的声明',
    layerOrder ?? '未找到',
    Boolean(layerOrder && layerOrder.includes('el')),
    'generateBundle 阶段的注入失效，打包上线后样式会错乱',
  )

  // ── ④ 命令式 API 的样式（真的弹一个出来量）
  list.push(await checkMessageBoxStyle())

  results.value = list
  running.value = false
}

onMounted(runChecks)
</script>

<template>
  <div ref="root" class="app-page">
    <!--
      机器可读结果快照（隐藏）。
      scripts/verify-style-check.sh 用无头浏览器加载本页后从这里提取 JSON 做断言。
    -->
    <pre data-testid="style-check-report" class="hidden">{{ reportJson }}</pre>

    <!-- 结果横幅 -->
    <div class="app-panel mb-5" data-testid="verdict">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 class="text-xl font-semibold">
            样式共存守门验证
            <span v-if="allPassed" class="ml-2 text-green-600">全部通过</span>
            <span v-else class="ml-2 text-red-600">存在未通过项</span>
          </h1>
          <p class="mt-1 text-sm text-gray-500">
            Element Plus × Tailwind CSS v4 —— 通过
            <strong>{{ passedCount }}/{{ totalCount }}</strong>
            项断言
          </p>
        </div>
        <el-button type="primary" :loading="running" @click="runChecks">重新检测</el-button>
      </div>
    </div>

    <!-- 断言结果明细 -->
    <div class="app-panel mb-5">
      <h2 class="mb-3 text-base font-semibold">断言明细</h2>
      <el-table :data="results" size="small" border style="width: 100%">
        <el-table-column prop="title" label="检查项" min-width="230" />
        <el-table-column label="结果" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.status === 'pass' ? 'success' : 'danger'" size="small">
              {{ row.status === 'pass' ? '通过' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="expected" label="期望" min-width="230" />
        <el-table-column prop="actual" label="实际" min-width="300" />
        <el-table-column label="排查方向" min-width="260">
          <template #default="{ row }">
            <span class="text-xs text-gray-500">{{ row.status === 'pass' ? '—' : row.hint }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 被断言的真实组件 -->
    <div class="app-panel mb-5">
      <h2 class="mb-3 text-base font-semibold">被断言的组件</h2>

      <div class="flex flex-wrap items-center gap-4">
        <el-button data-check="btn" type="primary">主按钮</el-button>
        <el-button>次按钮</el-button>
        <el-icon data-check="icon" :size="20">
          <Search />
        </el-icon>
        <div data-check="input-box">
          <el-input v-model="inputValue" placeholder="输入框" style="width: 220px" />
        </div>
      </div>

      <!-- 行内上下文：真正能检出 preflight 的场景 -->
      <p data-check="inline-text" class="mt-4" style="font-size: 16px; line-height: 24px">
        行内上下文中的图标：<el-icon :size="16"><Search /></el-icon> 应与文字在同一行，段落高度保持
        24px。
      </p>

      <div class="mt-4">
        <p class="mb-2 text-sm text-gray-500">
          以下按钮的父容器为整行宽度，工具类若失效则按钮只有文字宽度：
        </p>
        <el-button data-check="full-btn" type="primary" class="w-full">
          w-full 全宽按钮（应铺满整行）
        </el-button>
      </div>
    </div>

    <!-- 被断言的纯布局 -->
    <div class="app-panel">
      <h2 class="mb-3 text-base font-semibold">被断言的纯布局与基础元素</h2>

      <div data-check="flex" class="flex gap-4">
        <div class="app-panel flex-1 text-center">flex + gap-4 子项 A</div>
        <div class="app-panel flex-1 text-center">flex + gap-4 子项 B</div>
      </div>

      <div data-check="pad" class="p-4 mt-4 bg-gray-100">p-4 内边距（应看到 16px 内边距）</div>

      <p class="mt-6 text-sm text-gray-500">
        下面这个 <code>h1</code> 没有加任何字号类。若 preflight 生效，它会被重置为继承字号
        （14px、不加粗），看上去和正文一样 —— 这正是「preflight 会重置原生元素默认样式」的直接证据。
      </p>
      <h1 data-check="raw-h1">原生 h1 标题</h1>
    </div>
  </div>
</template>
