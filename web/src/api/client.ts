import axios, { type AxiosInstance, type AxiosError } from 'axios'

/**
 * 统一的 HTTP 客户端。
 *
 * 设计要点：
 *  1. baseURL 默认 '/api' —— 开发期由 Vite 代理、生产期由 Nginx 反代，
 *     前端代码不感知后端地址，部署形态切换零改动
 *  2. withCredentials: true —— 会话走 httpOnly Cookie，必须携带
 *  3. 请求头带 X-Request-ID 的接收方日志由后端生成，这里只透传响应头
 *  4. 统一错误结构：把后端的 { code, message, request_id } 归一化后抛出
 */

export interface ApiError {
  code: string
  message: string
  status: number
  requestId?: string
  /**
   * 结构化明细。**绝大多数错误都没有这个字段。**
   *
   * 它存在的唯一理由是批量导入：一份 500 行的文件里有 7 行不合格时，
   * 「导入失败」四个字毫无帮助，必须把「第几行、哪一列、什么值、为什么
   * 不合法」一并带回来，界面才能渲染出一张可定位的错误表。
   * 这些信息塞进 message 会变成一段没法解析的散文。
   *
   * 类型是 unknown 而不是 any：取用方必须自己收敛一次（见 assetImport.ts
   * 的 asImportPreview），否则「以为有 data、其实是 undefined」会在运行期
   * 才暴露。
   */
  data?: unknown
}

export class HttpError extends Error implements ApiError {
  code: string
  status: number
  requestId?: string
  data?: unknown

  constructor(payload: ApiError) {
    super(payload.message)
    this.name = 'HttpError'
    this.code = payload.code
    this.status = payload.status
    this.requestId = payload.requestId
    this.data = payload.data
  }
}

export const http: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30_000,
  withCredentials: true,
  headers: {
    Accept: 'application/json',
  },
})

// ------------------------------------------------------------------ 响应拦截

/** 错误响应体的形状。成功响应不经过这里，所以只列错误信封的字段。 */
interface ErrorBody {
  code?: string
  message?: string
  request_id?: string
  data?: unknown
}

/**
 * 二进制请求失败时把 Blob 读回 JSON 信封。
 *
 * 为什么需要这一步：`responseType: 'blob'` 之下，即使后端返回的是标准的
 * JSON 错误信封（例如下载模板没有权限时的 403），axios 也会把它包成 Blob。
 * 拦截器取不出 `code` / `message`，界面上就只剩「请求失败（HTTP 403）」——
 * 既没有错误码也没有原因，用户无法自助排查，我们也无法从截图里定位。
 *
 * @returns 不是 JSON（真的是一段二进制内容）时返回 null，此时保持原有的兜底文案
 */
async function parseBlobEnvelope(blob: Blob): Promise<ErrorBody | null> {
  try {
    const parsed: unknown = JSON.parse(await blob.text())
    if (typeof parsed === 'object' && parsed !== null) return parsed as ErrorBody
    return null
  } catch {
    return null
  }
}

http.interceptors.response.use(
  (response) => response,
  async (
    error: AxiosError<{
      code?: string
      message?: string
      request_id?: string
      data?: unknown
    }>,
  ) => {
    const status = error.response?.status ?? 0

    const raw: unknown = error.response?.data
    const body: ErrorBody | undefined =
      raw instanceof Blob
        ? ((await parseBlobEnvelope(raw)) ?? undefined)
        : (raw as ErrorBody | undefined)

    let code = body?.code ?? 'NETWORK_ERROR'
    let message = body?.message ?? ''

    if (!message) {
      if (status === 0) {
        message = '无法连接到服务器，请确认后端服务是否已启动'
      } else if (status === 401) {
        message = '登录状态已失效，请重新登录'
      } else if (status === 403) {
        message = '没有权限执行该操作'
      } else if (status >= 500) {
        message = '服务器内部错误，请稍后重试'
      } else {
        message = `请求失败（HTTP ${status}）`
      }
      code = body?.code ?? `HTTP_${status || 'NETWORK'}`
    }

    return Promise.reject(
      new HttpError({
        code,
        message,
        status,
        requestId: body?.request_id ?? error.response?.headers['x-request-id'],
        // 原样透传：这一层不认识任何业务形状，收敛交给消费方
        data: body?.data,
      }),
    )
  },
)
