#!/usr/bin/env node
/**
 * 前端端到端冒烟验证（真实浏览器）
 * ============================================================================
 * 为什么必须有这一层：
 *
 * 类型检查、ESLint、单元测试都只能证明「代码自洽」，证明不了「页面能用」。
 * 鉴权守卫、动态路由挂载、CSRF 头注入、静默刷新——这些逻辑的失效方式
 * 恰恰都是「编译通过、类型正确、运行时白屏或跳转错」。
 * 唯一能覆盖它们的办法就是把页面真的跑起来点一遍。
 *
 * 这个脚本用系统自带的 Chrome（无需下载 Chromium），通过 CDP 驱动：
 *   1. 匿名访问 / → 必须被守卫重定向到 /login，且登录表单已渲染
 *   2. 用管理员登录 → 进入总览，权限码下发，菜单按权限出现
 *   3. 访问用户管理页 → 表格真实渲染出数据（证明接口与契约打通）
 *   4. 用「无任何角色」的账号登录 → 菜单里不应出现任何业务入口，
 *      且直接敲 URL 访问 /system/users 必须落到 404
 *      （这条是动态路由设计的核心断言：未授权路由**根本没被注册**）
 *   5. 收尾：把临时账号禁用，避免污染环境
 *
 * 用法： node scripts/e2e-smoke.mjs --base http://127.0.0.1:4173 \
 *                                  --username admin --password <pwd>
 * ============================================================================
 */

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// ------------------------------------------------------------------ 参数

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]
    if (!token.startsWith('--')) continue
    out[token.slice(2)] = argv[i + 1]
    i++
  }
  return out
}

const args = parseArgs(process.argv.slice(2))
const BASE = (args.base ?? 'http://127.0.0.1:4173').replace(/\/$/, '')
const USERNAME = args.username
const PASSWORD = args.password
const CHROME_PATH =
  process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

if (!USERNAME || !PASSWORD) {
  console.error('缺少 --username / --password')
  process.exit(2)
}

const RED = '\u001b[31m'
const GREEN = '\u001b[32m'
const DIM = '\u001b[2m'
const RESET = '\u001b[0m'

let passed = 0
const failures = []

function ok(msg) {
  passed++
  console.log(`  ${GREEN}✅${RESET} ${msg}`)
}

function bad(msg) {
  failures.push(msg)
  console.log(`  ${RED}❌${RESET} ${msg}`)
}

function assert(cond, msg) {
  if (cond) ok(msg)
  else bad(msg)
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

// ------------------------------------------------------------------ CDP 客户端

class CDP {
  constructor(ws) {
    this.ws = ws
    this.seq = 0
    this.pending = new Map()

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id)
        this.pending.delete(msg.id)
        if (msg.error) reject(new Error(`${msg.error.message} (${JSON.stringify(msg.error)})`))
        else resolve(msg.result)
      }
    }
  }

  static async connect(url) {
    const ws = new WebSocket(url)
    await new Promise((resolve, reject) => {
      ws.onopen = resolve
      ws.onerror = () => reject(new Error(`CDP 连接失败: ${url}`))
    })
    return new CDP(ws)
  }

  send(method, params = {}) {
    const id = ++this.seq
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, method, params }))
    })
  }

  /** 在页面里求值。表达式抛错时直接失败，避免把 undefined 当成结果继续跑 */
  async evaluate(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    })
    if (res.exceptionDetails) {
      throw new Error(
        `页面内求值失败: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text}`,
      )
    }
    return res.result.value
  }

  async navigate(url) {
    await this.send('Page.navigate', { url })
    await this.waitForLoad()
  }

  async waitForLoad(timeout = 15000) {
    const start = Date.now()
    while (Date.now() - start < timeout) {
      // 等 SPA 挂载完成：Vue 会把内容塞进 #app
      const ready = await this.evaluate(
        `document.readyState === 'complete' && !!document.querySelector('#app') && document.querySelector('#app').children.length > 0`,
      ).catch(() => false)
      if (ready) return
      await sleep(120)
    }
    throw new Error('等待页面加载超时')
  }

  async waitFor(desc, predicate, timeout = 15000) {
    const start = Date.now()
    while (Date.now() - start < timeout) {
      if (await predicate().catch(() => false)) return
      await sleep(150)
    }
    throw new Error(`等待超时：${desc}`)
  }

  pathname() {
    return this.evaluate('location.pathname')
  }

  text() {
    return this.evaluate('document.body.innerText')
  }
}

// ------------------------------------------------------------------ 浏览器

async function launchChrome() {
  const debugPort = await freePort()
  const profileDir = mkdtempSync(join(tmpdir(), 'sr-e2e-'))

  const child = spawn(
    CHROME_PATH,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-features=Translate',
      `--user-data-dir=${profileDir}`,
      `--remote-debugging-port=${debugPort}`,
      '--window-size=1440,900',
      'about:blank',
    ],
    { stdio: 'ignore' },
  )

  // 等 DevTools 端口就绪
  const deadline = Date.now() + 20000
  let target = null
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${debugPort}/json/list`)
      const list = await res.json()
      target = list.find((t) => t.type === 'page')
      if (target?.webSocketDebuggerUrl) break
    } catch {
      /* 还没起来 */
    }
    await sleep(200)
  }

  if (!target?.webSocketDebuggerUrl) {
    child.kill('SIGKILL')
    throw new Error('Chrome DevTools 端口未就绪，无法建立连接')
  }

  return {
    child,
    wsUrl: target.webSocketDebuggerUrl,
    cleanup() {
      child.kill('SIGKILL')
      try {
        rmSync(profileDir, { recursive: true, force: true })
      } catch {
        /* 清理失败不影响结论 */
      }
    },
  }
}

// ------------------------------------------------------------------ 页面动作

/** 用原生 setter 赋值再派发 input 事件 —— Vue 的 v-model 只监听 input 事件 */
function fillLoginScript(username, password) {
  return `(() => {
    const inputs = [...document.querySelectorAll('input')]
    const user = inputs.find(i => i.type === 'text' || i.type === '')
    const pwd = inputs.find(i => i.type === 'password')
    if (!user || !pwd) return 'no-inputs'
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
    setter.call(user, ${JSON.stringify(username)})
    user.dispatchEvent(new Event('input', { bubbles: true }))
    setter.call(pwd, ${JSON.stringify(password)})
    pwd.dispatchEvent(new Event('input', { bubbles: true }))
    return 'ok'
  })()`
}

const CLICK_LOGIN = `(() => {
  const btn = [...document.querySelectorAll('button')]
    .find(b => b.textContent.replace(/\\s/g, '').includes('登录'))
  if (!btn) return 'no-button'
  btn.click()
  return 'ok'
})()`

/** 改密表单有三个密码框，DOM 顺序即「原密码 / 新密码 / 确认新密码」 */
function fillPasswordFormScript(oldPassword, newPassword) {
  return `(() => {
    const pwds = [...document.querySelectorAll('input[type=password]')]
    if (pwds.length < 3) return 'expected-3-password-inputs-got-' + pwds.length
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
    const values = [${JSON.stringify(oldPassword)}, ${JSON.stringify(newPassword)}, ${JSON.stringify(newPassword)}]
    pwds.slice(0, 3).forEach((el, i) => {
      setter.call(el, values[i])
      el.dispatchEvent(new Event('input', { bubbles: true }))
    })
    return 'ok'
  })()`
}

const CLICK_CHANGE_PASSWORD = `(() => {
  const btn = [...document.querySelectorAll('button')]
    .find(b => b.textContent.replace(/\\s/g, '').includes('确认修改'))
  if (!btn) return 'no-button'
  btn.click()
  return 'ok'
})()`

/**
 * 登录，并处理「首次登录必须改密」。
 *
 * 引导流程创建的管理员、以及管理员新建的账号都带 must_change_password，
 * 登录后守卫会先把人送到 /change-password，不完成改密就访问不到任何业务页面。
 *
 * 这不是测试的障碍，而是必须验证的一条链路：初始密码不改掉，就应当
 * 什么都干不了。因此这里如实走一遍，并把改后的密码返回给调用方。
 *
 * @returns 本次会话实际生效的密码
 */
async function loginAndSettle(cdp, username, password, nextPassword) {
  await loginAs(cdp, username, password)

  let settled
  try {
    settled = await cdp
      .waitFor(
        '登录后的落点',
        async () => {
          const p = await cdp.pathname()
          return HOME_PATHS.has(p) || p === '/change-password'
        },
        12000,
      )
      .then(() => cdp.pathname())
  } catch (err) {
    // 登录失败最有价值的诊断信息是「页面上有没有报错、报的是什么」。
    // 不带上下文地抛一句「等待超时」，排查得从后端访问日志翻起，
    // 而这里一句话就能说清是凭据错、CSRF 被拦还是白屏。
    const path = await cdp.pathname().catch(() => '(取不到)')
    const text = await cdp
      .evaluate('document.body.innerText')
      .then((t) => t.replace(/\s+/g, ' | ').slice(0, 400))
      .catch(() => '(取不到)')
    throw new Error(`${err.message}\n  当前路径: ${path}\n  页面内容: ${text}`, { cause: err })
  }

  if (settled !== '/change-password') return password

  const filled = await cdp.evaluate(fillPasswordFormScript(password, nextPassword))
  if (filled !== 'ok') throw new Error(`填写改密表单失败: ${filled}`)

  const clicked = await cdp.evaluate(CLICK_CHANGE_PASSWORD)
  if (clicked !== 'ok') throw new Error(`提交改密失败: ${clicked}`)

  await cdp.waitFor('改密后进入总览页', async () => isHome(cdp))
  ok('首次登录被强制跳转到改密页，改密后放行（强制改密链路生效）')

  return nextPassword
}

/**
 * 在页面上下文里直接调接口。
 *
 * 这样做而不是从外部 curl，是因为它顺带验证了一件重要的事：
 * 前端确实能从 Cookie 里读到 CSRF 令牌并把它放进请求头 ——
 * 这正是「双提交」方案能否成立的关键，纯外部调用测不到。
 */
function apiCallScript(method, path, body) {
  return `(async () => {
    const csrf = document.cookie
      .split('; ')
      .find(c => c.startsWith('sr_csrf='))
      ?.slice('sr_csrf='.length) ?? ''
    const res = await fetch(${JSON.stringify(path)}, {
      method: ${JSON.stringify(method)},
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': decodeURIComponent(csrf),
      },
      body: ${body ? `JSON.stringify(${JSON.stringify(body)})` : 'undefined'},
    })
    return { status: res.status, body: await res.text() }
  })()`
}

/**
 * 读取侧栏菜单的可见文本（先展开所有分组）。
 *
 * ⚠️ 这一步不能用 `textContent`：
 *
 * 分组菜单（el-sub-menu）的子树在展开前是 `display: none`。
 * `textContent` 无视渲染状态，会把隐藏项也算进来——于是
 * 「无权限账号不该看到用户管理」这条断言就变成了假通过：
 * 哪怕菜单项真的在那里、只是被折叠着，测试也照样绿灯。
 *
 * 所以这里先点开全部分组，再用 `innerText` 取**用户实际看得见**的文字。
 * 代价是多两步交互，换来的是断言真的在测东西。
 */
async function readExpandedMenu(cdp) {
  await cdp.evaluate(`(() => {
    document.querySelectorAll('.app-menu .el-sub-menu__title').forEach(el => el.click())
    return 'ok'
  })()`)
  await sleep(400)
  return cdp.evaluate(`document.querySelector('.app-menu')?.innerText ?? ''`)
}

// ------------------------------------------------------------------ 主流程

const TEMP_USER = `e2e_tmp_${Date.now().toString(36)}`
const TEMP_INITIAL_PASSWORD = 'E2eTemp!2024'
const TEMP_NEW_PASSWORD = 'E2eTemp!2024-changed'
/**
 * 登录后的落地页。
 *
 * 根路径 `/` 挂的是带 layout 的父路由，它会 redirect 到 `/dashboard`，
 * 因此「已进入主界面」的判据是这两个路径之一 —— 只认 `/` 会一直等不到。
 */
const HOME_PATHS = new Set(['/', '/dashboard'])
const isHome = async (cdp) => HOME_PATHS.has(await cdp.pathname())

/** 引导管理员首次登录后必须改成的密码 */
const ADMIN_NEW_PASSWORD = `${PASSWORD.slice(0, 100)}-e2e`

async function loginAs(cdp, username, password) {
  await cdp.waitFor('登录表单出现', async () =>
    cdp.evaluate(`!!document.querySelector('input[type=password]')`),
  )
  const filled = await cdp.evaluate(fillLoginScript(username, password))
  if (filled !== 'ok') throw new Error(`填写登录表单失败: ${filled}`)

  const clicked = await cdp.evaluate(CLICK_LOGIN)
  if (clicked !== 'ok') throw new Error(`点击登录按钮失败: ${clicked}`)
}

async function logout(cdp) {
  await cdp.evaluate(apiCallScript('POST', '/api/auth/logout'))
}

async function main() {
  const browser = await launchChrome()
  let cdp

  try {
    cdp = await CDP.connect(browser.wsUrl)
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')

    // ── 1. 匿名访问 ───────────────────────────────────────────────
    console.log(`\n── 1. 匿名访问必须被守卫拦到登录页 ──`)
    await cdp.navigate(`${BASE}/`)
    await cdp.waitFor('重定向到 /login', async () => (await cdp.pathname()) === '/login')

    assert((await cdp.pathname()) === '/login', '访问 / 被重定向到 /login')
    const loginText = await cdp.text()
    assert(loginText.includes('网络安全风险评估助手'), '登录页渲染出应用标题')
    assert(loginText.includes('请使用管理员分配的账号登录'), '登录页渲染出表单说明')
    assert(
      await cdp.evaluate(`!!document.querySelector('input[type=password]')`),
      '登录页渲染出密码输入框（Element Plus 组件正常挂载）',
    )

    // 样式是否真的加载：Element Plus 的按钮有背景色，被 Tailwind 压过会是透明
    const btnBg = await cdp.evaluate(
      `getComputedStyle([...document.querySelectorAll('button')].find(b=>b.textContent.includes('登录'))).backgroundColor`,
    )
    assert(
      btnBg && btnBg !== 'rgba(0, 0, 0, 0)' && btnBg !== 'transparent',
      `登录按钮有实际背景色（CSS 分层生效）：${btnBg}`,
    )

    // ── 2. 管理员登录 ─────────────────────────────────────────────
    console.log(`\n── 2. 管理员登录与权限下发 ──`)
    const adminPassword = await loginAndSettle(cdp, USERNAME, PASSWORD, ADMIN_NEW_PASSWORD)
    if (adminPassword === PASSWORD) {
      ok('管理员登录成功（该账号已完成过首次改密）')
    }
    await cdp.waitFor('进入总览页', async () => isHome(cdp))
    ok(`登录成功并跳转到 ${await cdp.pathname()}`)

    // ── 2b. 身份与权限上下文确实渲染到了界面 ─────────────────────────
    // P6 把总览页从「占位页（自带身份区块与权限码水印）」重写成真实仪表盘，
    // 旧断言（页面文本含「当前登录身份」/ USERNAME / 'user:read'）随之失效。
    //
    // 这些信息现在渲染在 DefaultLayout 的顶栏：
    //   .app-user__name     = /auth/me 的 display_name（为空回退 username）
    //   .app-header .el-tag = /auth/me 的 roles
    // 与 /auth/me **逐字比对**而不是只判非空：这样它同时证明两件事 ——
    // 「身份到了界面」与「界面显示的正是当前这个会话的身份」。
    //
    // 至于旧断言里「后端下发的权限码已渲染（权限驱动的基础）」，它的现代等价
    // 证明在第 3 节与第 5 节：菜单按权限出现 / 不出现，比「页面文本里出现过
    // 权限码字符串」更接近这条守门真正要防的失效模式（权限没生效、越权可见）。
    const me = await cdp.evaluate(`fetch('/api/auth/me').then(r => r.json())`)
    const meData = me?.data ?? {}
    const expectedName = meData.display_name || meData.username || ''
    assert(expectedName.length > 0, '/auth/me 返回了身份（display_name 或 username）')

    const shownName = await cdp.evaluate(
      `(document.querySelector('.app-user__name')?.textContent ?? '').trim()`,
    )
    assert(shownName.length > 0, '顶栏渲染出登录身份区块（.app-user__name）')
    assert(
      shownName === expectedName,
      `顶栏显示名与 /auth/me 一致：界面「${shownName}」= 接口「${expectedName}」`,
    )

    const roleTagCount = await cdp.evaluate(
      `document.querySelectorAll('.app-header .el-tag').length`,
    )
    assert(
      (meData.roles?.length ?? 0) >= 1 && roleTagCount === meData.roles.length,
      `后端下发的角色已渲染：${roleTagCount} 个角色标签 = /auth/me 的 ${meData.roles?.length ?? 0} 个`,
    )

    // ── 3. 动态菜单 ───────────────────────────────────────────────
    console.log(`\n── 3. 菜单由权限驱动 ──`)
    const menuText = await readExpandedMenu(cdp)
    assert(menuText.includes('用户管理'), '管理员菜单出现「用户管理」')
    assert(menuText.includes('审计日志'), '管理员菜单出现「审计日志」')
    assert(menuText.includes('总览'), '菜单出现「总览」')

    // ── 4. 用户管理页真实取数 ─────────────────────────────────────
    console.log(`\n── 4. 用户管理页与契约打通 ──`)
    await cdp.navigate(`${BASE}/system/users`)
    await cdp.waitFor('用户表格出现数据', async () => {
      const t = await cdp.evaluate(`document.querySelector('.el-table')?.innerText ?? ''`)
      return t.includes(USERNAME)
    })
    ok('用户列表接口调用成功，表格渲染出数据')

    const usersText = await cdp.text()
    assert(usersText.includes('新建用户'), '有 user:write 时显示「新建用户」按钮')

    // ── 5. 创建无角色账号，验证未授权路由不会被注册 ───────────────
    console.log(`\n── 5. 无权限账号：未授权路由根本不存在 ──`)
    const created = await cdp.evaluate(
      apiCallScript('POST', '/api/users', {
        username: TEMP_USER,
        display_name: 'E2E 临时账号',
        password: TEMP_INITIAL_PASSWORD,
        roles: [],
      }),
    )
    assert(created.status === 201, `通过页面上下文创建无角色账号（HTTP ${created.status}）`)

    await logout(cdp)
    await cdp.navigate(`${BASE}/`)
    await cdp.waitFor('回到登录页', async () => (await cdp.pathname()) === '/login')

    await loginAndSettle(cdp, TEMP_USER, TEMP_INITIAL_PASSWORD, TEMP_NEW_PASSWORD)
    await cdp.waitFor('进入总览页', async () => isHome(cdp))
    ok('无角色账号登录成功（账号可用，但没有任何权限）')

    // 同样先展开分组再读：无权限账号这里本就不该有分组，
    // 但断言口径必须与管理员侧一致，否则「测的东西不一样」会导致虚假通过
    const emptyMenu = await readExpandedMenu(cdp)
    assert(!emptyMenu.includes('用户管理'), '无权限账号菜单中不出现「用户管理」')
    assert(!emptyMenu.includes('审计日志'), '无权限账号菜单中不出现「审计日志」')
    assert(emptyMenu.includes('总览'), '无权限账号仍可见「总览」（无需权限的页面）')

    await cdp.navigate(`${BASE}/system/users`)
    await sleep(600)
    const blockedText = await cdp.text()
    assert(
      blockedText.includes('页面不存在') || blockedText.includes('无访问权限'),
      '直接敲 URL 访问 /system/users 被拦（未授权路由未被动态注册）',
    )

    // ── 6. 收尾 ───────────────────────────────────────────────────
    console.log(`\n── 6. 清理临时账号 ──`)
    await logout(cdp)
    await cdp.navigate(`${BASE}/`)
    await cdp.waitFor('回到登录页', async () => (await cdp.pathname()) === '/login')
    await loginAndSettle(cdp, USERNAME, adminPassword, adminPassword)
    await cdp.waitFor('重新进入总览页', async () => isHome(cdp))

    const listRes = await cdp.evaluate(
      apiCallScript('GET', `/api/users?keyword=${TEMP_USER}&pageSize=5`),
    )
    const listJson = JSON.parse(listRes.body)
    const tempUser = listJson?.data?.items?.[0]
    if (tempUser) {
      const disabled = await cdp.evaluate(
        apiCallScript('PATCH', `/api/users/${tempUser.id}`, { status: 'disabled' }),
      )
      assert(disabled.status === 200, '临时账号已禁用（保留记录以维持审计可追溯）')
    } else {
      bad('未能查到临时账号，清理未完成')
    }
  } finally {
    browser.cleanup()
  }

  // ── 汇总 ────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════')
  if (failures.length === 0) {
    console.log(`${GREEN}前端端到端冒烟验证全部通过 ✅  通过 ${passed} 项${RESET}`)
    console.log('══════════════════════════════════════════')
  } else {
    console.log(`${RED}存在失败项 ❌  通过 ${passed}/${passed + failures.length} 项${RESET}`)
    console.log('失败清单：')
    failures.forEach((f) => console.log(`  - ${f}`))
    console.log('══════════════════════════════════════════')
    process.exitCode = 1
  }
}

main().catch((err) => {
  console.error(`\n${RED}冒烟验证中断：${err.message}${RESET}`)
  console.error(`${DIM}${err.stack}${RESET}`)
  process.exitCode = 1
})
