/**
 * 后端 REST 客户端：Cookie 会话 + CSRF 双提交 + 过期自动重登。
 *
 * ── 为什么是「登录一个真实账号」而不是带一个长期 API Token ──────────────
 *
 * 本服务不引入第二套身份体系。它做的每一步都走前端同样的接口，
 * 于是三件事自动成立：**认证（Authn）、授权（RBAC）、审计（Audit）**
 * 全部照常生效。MCP 因此不是一条绕过权限的后门：
 *
 *   - 服务账号的角色决定它能调哪些接口，越权得到的是后端的 403，
 *     而不是「MCP 自己判断了一下就不发了」；
 *   - 每次写操作都会在后端留下审计记录，责任人就是这个服务账号；
 *   - 权限一变，MCP 的能力立刻跟着变，不需要在 MCP 侧同步任何东西。
 *
 * 反过来说，任何在 MCP 侧做的权限判断都只是**体验层**，不能作为安全边界。
 */

import { ConfigError } from './config.js'

const CSRF_COOKIE = 'sr_csrf'
const CSRF_HEADER = 'X-CSRF-Token'
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const AUTH_PATH_PREFIX = '/api/auth/'

/** 命中这些错误码时，「重新认证一次再重发」才是正确动作 */
const REAUTH_CODES = new Set(['AUTH_TOKEN_EXPIRED', 'AUTH_TOKEN_INVALID', 'UNAUTHORIZED'])

export class ApiError extends Error {
  constructor({ status, code, message, requestId, path }) {
    super(message || `HTTP ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
    this.path = path
  }

  /** 供工具层拼出「谁拒绝的、为什么」的一句话 */
  toToolMessage() {
    const bits = [`HTTP ${this.status}`, this.code]
    if (this.requestId) bits.push(`request_id=${this.requestId}`)
    return `${this.message}（${bits.join(' / ')}）`
  }
}

/**
 * 极简 Cookie Jar。
 *
 * Node 的 fetch（undici）**不会**自动存取 Cookie，所以这里手工实现。
 * 实现里唯一不能省的细节是 Cookie 的 `Path`：
 * 后端的刷新令牌 `sr_rt` 被刻意限制在 `/api/auth` 下发送（见
 * server/internal/auth/cookie.go 的 RefreshCookiePath），
 * 原因是不希望它出现在每一个业务请求里。一个忽略 Path 的 jar
 * 会把它发给所有接口——**功能上照样能跑**，所以这个错误不会被任何
 * 冒烟测试发现，只会静默地把一枚 7 天有效的凭据摊薄到每个请求上。
 */
class CookieJar {
  #cookies = new Map()

  /** Set-Cookie 头可能有多条，用 getSetCookie() 逐条取（Node >= 20） */
  absorb(response) {
    const raw = response.headers.getSetCookie?.() ?? []
    for (const line of raw) {
      const [pair] = line.split(';')
      const eq = pair.indexOf('=')
      if (eq <= 0) continue
      const name = pair.slice(0, eq).trim()
      const value = pair.slice(eq + 1).trim()
      // 删除型 Set-Cookie（Max-Age=0）在后端是 logout 用的，
      // 不删除的话登出之后依旧带着旧令牌重发
      if (value === '' || /max-age=0/i.test(line)) this.#cookies.delete(name)
      else this.#cookies.set(name, value)
    }
  }

  get(name) {
    return this.#cookies.get(name) ?? ''
  }

  clear() {
    this.#cookies.clear()
  }

  /**
   * 按 Path 前缀规则拼出 Cookie 头。
   *
   * 只做**前缀匹配**：RFC 6265 的完整路径匹配规则（含 `-Path` 变体）
   * 在这里用不上，后端只用了 `/` 与 `/api/auth` 两个路径，
   * 而实现一个半对的完整匹配比明确的前缀匹配更容易出错。
   */
  headerFor(path) {
    const parts = []
    for (const [name, value] of this.#cookies) {
      if (name === 'sr_rt' && !path.startsWith(AUTH_PATH_PREFIX)) continue
      parts.push(`${name}=${value}`)
    }
    return parts.join('; ')
  }
}

export class ApiClient {
  #config
  #jar = new CookieJar()
  #csrfToken = ''
  /** 单飞：并发的工具调用不应各自触发一次登录（会互相把会话顶掉） */
  #authInFlight = null

  constructor(config) {
    this.#config = config
  }

  /** 仅供测试与诊断：当前会话里有哪些 Cookie 名（不含值） */
  cookieNames() {
    const names = []
    for (const name of ['sr_at', 'sr_rt', 'sr_csrf']) {
      if (this.#jar.get(name)) names.push(name)
    }
    return names
  }

  // ---------------------------------------------------------------- CSRF

  async #ensureCsrf(force = false) {
    if (!force && this.#csrfToken) return this.#csrfToken

    const res = await this.#fetch({
      method: 'GET',
      path: '/api/auth/csrf',
      skipCsrf: true,
    })
    const token = this.#jar.get(CSRF_COOKIE) || res.body?.data?.csrf_token || ''
    if (!token) throw new ConfigError('后端没有下发 CSRF 令牌，无法登录')
    this.#csrfToken = token
    return token
  }

  // ---------------------------------------------------------------- 认证

  /** 登录（或重新登录）。并发调用会被合并成一次 */
  async ensureSession() {
    if (this.#authInFlight) return this.#authInFlight
    this.#authInFlight = this.#login().finally(() => {
      this.#authInFlight = null
    })
    return this.#authInFlight
  }

  async #login() {
    await this.#ensureCsrf(true)
    const res = await this.#fetch({
      method: 'POST',
      path: '/api/auth/login',
      body: { username: this.#config.username, password: this.#config.password },
    })
    // 登录会**轮换** CSRF 令牌；不同步的话后续写请求全部 403，
    // 而症状看起来像权限问题（AUTH_CSRF_INVALID），极难定位
    this.#csrfToken = this.#jar.get(CSRF_COOKIE) || this.#csrfToken
    return res.body?.data ?? {}
  }

  async #refresh() {
    await this.#ensureCsrf()
    const res = await this.#fetch({
      method: 'POST',
      path: '/api/auth/refresh',
      skipCsrf: false,
      retried: true,
    })
    this.#csrfToken = this.#jar.get(CSRF_COOKIE) || this.#csrfToken
    return res.body?.data ?? {}
  }

  // ---------------------------------------------------------------- 传输

  async #fetch({ method, path, query, body, skipCsrf = false, retried = false }) {
    const url = new URL(this.#config.baseUrl + path)
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null || value === '') continue
        url.searchParams.set(key, String(value))
      }
    }

    const headers = { Accept: 'application/json' }
    const cookie = this.#jar.headerFor(path)
    if (cookie) headers.Cookie = cookie
    if (!SAFE_METHODS.has(method) && !skipCsrf) {
      headers[CSRF_HEADER] = await this.#ensureCsrf()
    }
    if (body !== undefined) headers['Content-Type'] = 'application/json'

    let response
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        // 超时用 AbortSignal.timeout：MCP 的一次工具调用若卡住，
        // 客户端看到的是「模型不响应」，比一个明确的超时错误难排查得多
        signal: AbortSignal.timeout(this.#config.timeoutMs),
        redirect: 'error',
      })
    } catch (err) {
      throw new ApiError({
        status: 0,
        code: 'MCP_UPSTREAM_UNREACHABLE',
        message: `无法连接后端 ${this.#config.baseUrl}：${err?.message ?? err}`,
        path,
      })
    }

    this.#jar.absorb(response)

    // 401 处理分两层：先用刷新令牌换新会话（常态，15 分钟后就会发生），
    // 刷新也救不回来才重新登录。只重试一次，避免凭据错误时进入死循环。
    if (response.status === 401 && !retried) {
      const parsed = await readEnvelope(response)
      if (REAUTH_CODES.has(parsed.code)) {
        const recovered = await this.#recover()
        if (recovered) {
          return this.#fetch({ method, path, query, body, skipCsrf, retried: true })
        }
      }
      throw toApiError(parsed, response, path)
    }

    const parsed = await readEnvelope(response)
    if (!response.ok) throw toApiError(parsed, response, path)
    return parsed
  }

  /** 先刷新、失败则重登。返回「会话是否可能已恢复」 */
  async #recover() {
    try {
      await this.#refresh()
      return true
    } catch {
      // 刷新失败是常态（刷新令牌也过期了），继续走重登
    }
    try {
      this.#jar.clear()
      this.#csrfToken = ''
      await this.ensureSession()
      return true
    } catch (err) {
      // 重登失败说明凭据本身有问题，这是**部署问题**而不是业务错误，
      // 必须原样抛出，否则会被上层当成「这次调用运气不好」而吞掉
      if (err instanceof ApiError) return false
      throw err
    }
  }

  // ---------------------------------------------------------------- 对外

  /**
   * 发起一次业务请求，返回信封里的 `data`。
   *
   * 首次调用会先建立会话；之后每 15 分钟由 401 分支自动续期，
   * 调用方不需要关心。
   */
  async request(method, path, options = {}) {
    if (!this.#csrfToken) await this.ensureSession()
    const res = await this.#fetch({ method, path, ...options })
    return res.body?.data
  }

  get(path, query) {
    return this.request('GET', path, { query })
  }
}

// -------------------------------------------------------------------- 工具

/**
 * 解析响应信封。
 *
 * 刻意**不假设**响应一定是 JSON：后端有网关/代理挡在前面时，
 * 502 之类的错误可能返回一页 HTML。直接 `response.json()` 会抛出一个
 * 「Unexpected token <」的语法错误，把真正的原因（上游挂了）盖掉。
 */
async function readEnvelope(response) {
  const text = await response.text()
  if (!text) return { status: response.status, code: '', message: '', body: null }
  try {
    const json = JSON.parse(text)
    return {
      status: response.status,
      code: typeof json?.code === 'string' ? json.code : '',
      message: typeof json?.message === 'string' ? json.message : '',
      requestId: json?.request_id,
      body: json,
    }
  } catch {
    return {
      status: response.status,
      code: '',
      message: text.slice(0, 200),
      body: null,
    }
  }
}

function toApiError(parsed, response, path) {
  return new ApiError({
    status: response.status,
    code: parsed.code || `HTTP_${response.status}`,
    message: parsed.message || response.statusText || '请求失败',
    requestId: parsed.requestId,
    path,
  })
}
