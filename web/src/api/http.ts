/**
 * 业务请求封装：CSRF 注入、信封拆解、401 静默刷新。
 *
 * 为什么要在 `client.ts` 之上再包一层，而不是把逻辑塞进 axios 拦截器：
 * 拦截器只能改写「响应」，无法重放「原请求」。而静默刷新的本质是
 * 「用刷新令牌换新会话，然后把刚才失败的请求重发一遍」——
 * 这件事必须发生在能拿到原始请求配置的位置。
 */
import type { AxiosRequestConfig, AxiosResponse } from 'axios'

import { http, HttpError } from './client'
import type { CsrfToken } from './endpoints'

/** 与后端 auth 包中的常量保持一致（见 server/internal/auth/cookie.go） */
const CSRF_COOKIE = 'sr_csrf'
const CSRF_HEADER = 'X-CSRF-Token'

const SAFE_METHODS = new Set(['get', 'head', 'options'])

/**
 * 不需要（也无法）走「刷新后重试」的端点。
 *
 * 刷新令牌本身若返回 401，说明会话已经彻底结束，再刷新只会无限递归；
 * 登录与取令牌则根本还没有会话可刷。
 */
const NO_RETRY_PATHS = [
  '/auth/login',
  '/auth/refresh',
  '/auth/csrf',
  '/auth/logout',
  '/auth/password',
]

/** 命中这些错误码时，「重复上一次请求」才是正确动作 */
const REFRESHABLE_CODES = new Set(['AUTH_TOKEN_EXPIRED', 'AUTH_TOKEN_INVALID'])

// ------------------------------------------------------------------ CSRF

/**
 * 双提交令牌的内存缓存。
 *
 * 为什么缓存而不是每次现读 Cookie：开发环境下前端与后端分端口，
 * 浏览器对跨端口 Cookie 的策略不一致，读不到就得回退到请求接口取。
 * 缓存一层可以把这条回退路径收敛到「应用启动 + 会话轮换」两个时刻。
 */
let csrfToken = ''

function readCookie(name: string): string {
  const prefix = `${name}=`
  for (const part of document.cookie.split(';')) {
    const item = part.trim()
    if (item.startsWith(prefix)) {
      return decodeURIComponent(item.slice(prefix.length))
    }
  }
  return ''
}

/** 由登录 / 刷新响应更新缓存：会话轮换时后端会一并换掉 CSRF 令牌 */
export function setCsrfToken(token: string): void {
  csrfToken = token
}

export function clearCsrfToken(): void {
  csrfToken = ''
}

/**
 * 取得可用的 CSRF 令牌，必要时向后端索取。
 *
 * @param force 会话刚轮换时用 true，跳过缓存直接取新的
 */
export async function ensureCsrfToken(force = false): Promise<string> {
  if (!force && csrfToken) return csrfToken

  if (!force) {
    const fromCookie = readCookie(CSRF_COOKIE)
    if (fromCookie) {
      csrfToken = fromCookie
      return csrfToken
    }
  }

  const res = await http.get<{ data?: CsrfToken }>('/auth/csrf')
  csrfToken = res.data?.data?.csrf_token ?? ''
  return csrfToken
}

// ------------------------------------------------------------------ 会话失效通知

/**
 * 会话彻底失效时的回调。
 *
 * 用回调而不是在 api 层 import router：否则 api → router → store → api
 * 会形成循环依赖，且 api 层会被迫知道路由结构这件与它无关的事。
 * 由应用入口在启动时注入实际处理。
 */
let sessionExpiredHandler: (() => void) | null = null

export function onSessionExpired(handler: () => void): void {
  sessionExpiredHandler = handler
}

// ------------------------------------------------------------------ 静默刷新

/**
 * 并发合并用的单飞 Promise。
 *
 * ⚠️ 这个变量不是性能优化，而是**正确性要求**：
 * 后端对刷新令牌实现了轮换 + 重放检测。若页面上并发的两个请求各自
 * 触发一次刷新，第二个到达的请求会带着「已被使用过」的令牌——
 * 后端会判定为令牌泄漏，进而吊销整条会话链，用户被强制踢下线。
 * 合并成一次刷新可以从根本上避免这个自伤。
 */
let refreshInFlight: Promise<boolean> | null = null

async function doRefresh(): Promise<boolean> {
  try {
    const token = await ensureCsrfToken(true)
    const res = await http.post<{ data?: { csrf_token?: string } }>('/auth/refresh', null, {
      headers: { [CSRF_HEADER]: token },
    })
    // 轮换后的会话带新的 CSRF 令牌，必须同步更新，否则后续写请求全被 403
    const next = res.data?.data?.csrf_token
    if (next) setCsrfToken(next)
    return true
  } catch {
    return false
  }
}

function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = doRefresh().finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

// ------------------------------------------------------------------ 请求核心

interface Envelope<T> {
  code: string
  message: string
  data?: T
  request_id?: string
}

/** 判断响应体是否为业务信封 */
function isEnvelope(body: unknown): body is Envelope<unknown> {
  return typeof body === 'object' && body !== null && 'code' in body && 'message' in body
}

function toHttpError(err: unknown): HttpError {
  if (err instanceof HttpError) return err
  return new HttpError({
    code: 'NETWORK_ERROR',
    message: err instanceof Error ? err.message : '请求失败',
    status: 0,
  })
}

/**
 * 发起一次请求，返回**原始响应**。
 *
 * 这里承担的是「每一次业务请求都必须经历的那几步」：写方法注入 CSRF、
 * 401 时用刷新令牌换会话并把原请求重发一遍、彻底失效时通知外层跳登录、
 * 失败统一收敛成 `HttpError`。
 *
 * 它与 `request` 分家的理由只有一个：下载类请求需要读响应头
 * （文件名在 `Content-Disposition` 里），而 `request` 只把拆完信封的
 * `data` 交出去。分家后两层各自单一——`send` 只管「把请求发出去并
 * 让会话保持有效」，`request` 只管「拆信封」。
 *
 * @param retried 内部参数，避免「刷新成功但重试仍 401」时无限递归
 */
async function send<T = unknown>(
  config: AxiosRequestConfig,
  retried = false,
): Promise<AxiosResponse<T>> {
  const method = (config.method ?? 'get').toLowerCase()

  // 写请求必须带 CSRF 头。安全方法不带，也就省掉了一次可能的取令牌往返。
  if (!SAFE_METHODS.has(method)) {
    config.headers = { ...config.headers, [CSRF_HEADER]: await ensureCsrfToken() }
  }

  try {
    return await http.request<T>(config)
  } catch (raw) {
    const err = toHttpError(raw)
    const url = config.url ?? ''
    const canRetry =
      !retried &&
      err.status === 401 &&
      REFRESHABLE_CODES.has(err.code) &&
      !NO_RETRY_PATHS.some((p) => url.startsWith(p))

    if (canRetry && (await refreshSession())) {
      return send<T>(config, true)
    }

    // 走到这里意味着 401 已经无解：要么刷新失败，要么刷新后重试仍然 401。
    // 两种情况下会话都已真正结束，必须通知外层跳登录——
    // 否则页面会停在一个「什么都点不动、也不告诉你为什么」的状态。
    if (err.status === 401 && !NO_RETRY_PATHS.some((p) => url.startsWith(p))) {
      clearCsrfToken()
      sessionExpiredHandler?.()
    }

    throw err
  }
}

/**
 * 发起业务请求并拆掉信封，直接返回 `data`。
 */
async function request<T>(config: AxiosRequestConfig): Promise<T> {
  const res = await send(config)
  const body = res.data
  if (isEnvelope(body)) return body.data as T
  // 运维探针（/healthz、/health、/version）刻意不套信封
  return body as T
}

// ------------------------------------------------------------------ 对外 API

export const api = {
  get: <T>(url: string, config?: AxiosRequestConfig) =>
    request<T>({ ...config, url, method: 'get' }),

  post: <T>(url: string, body?: unknown, config?: AxiosRequestConfig) =>
    request<T>({ ...config, url, method: 'post', data: body }),

  patch: <T>(url: string, body?: unknown, config?: AxiosRequestConfig) =>
    request<T>({ ...config, url, method: 'patch', data: body }),

  put: <T>(url: string, body?: unknown, config?: AxiosRequestConfig) =>
    request<T>({ ...config, url, method: 'put', data: body }),

  delete: <T>(url: string, config?: AxiosRequestConfig) =>
    request<T>({ ...config, url, method: 'delete' }),

  /**
   * 需要读响应头的请求：返回**完整响应**而不是拆完信封的 `data`。
   *
   * 目前唯一的调用方是报告导出 —— 文件名在 `Content-Disposition` 里，
   * 只给 data 就把它丢了，用户下载到的文件会叫 "download"。
   *
   * 其余行为与 `post` 完全一致：CSRF 照样注入、401 照样静默刷新后重试、
   * 失败一样收敛成 `HttpError`（二进制响应体里的 JSON 错误信封由
   * client.ts 的响应拦截器读回，见 `parseBlobEnvelope`）。
   *
   * ⚠️ `config.responseType` 由调用方指定，本方法不做默认——
   * 调用方要的是二进制还是 JSON，是它自己的事，在这里猜一个默认值
   * 只会让「忘了写 responseType」变成一个静默的错误。
   */
  download: <T = Blob>(config: AxiosRequestConfig): Promise<AxiosResponse<T>> => send<T>(config),
}

export { HttpError }
