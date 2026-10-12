/**
 * MCP Server 的运行配置。
 *
 * 全部来自环境变量，**没有任何配置文件**：MCP 客户端（Claude Desktop、
 * IDE 插件等）都是用「env」字段来传这些值的，多一份配置文件就多一处
 * 「界面里配了不生效」的来源。
 *
 * 校验刻意放在**进程启动时**，并且失败时以非零退出码退出（见 index.js：
 * 用 `process.exitCode` 而不是 `process.exit()`，后者会截断尚未落盘的 stderr）：
 * 一个连不上后端的 MCP Server 表现为「每个工具都报错」，
 * 而那看起来像工具本身有问题。宁可起不来，也不要起一个只会报错的壳。
 */

/** 允许的写开关取值。写成集合而不是 `=== 'true'`：`1` / `yes` 是运维最常写的两种 */
const TRUE_VALUES = new Set(['true', '1', 'yes', 'on'])

const DEFAULT_BASE_URL = 'http://127.0.0.1:8080'
const DEFAULT_TIMEOUT_MS = 15000
const MIN_TIMEOUT_MS = 1000
const MAX_TIMEOUT_MS = 60000

export class ConfigError extends Error {}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min
  return Math.min(max, Math.max(min, Math.trunc(value)))
}

/**
 * 读配置。`env` 参数是为测试留的注入点（默认取 process.env）。
 */
export function loadConfig(env = process.env) {
  const rawBase = String(env.SR_MCP_API_BASE ?? '').trim()
  const baseUrl = (rawBase || DEFAULT_BASE_URL).replace(/\/+$/, '')

  let parsed
  try {
    parsed = new URL(baseUrl)
  } catch {
    throw new ConfigError(`SR_MCP_API_BASE 不是合法 URL：${baseUrl}`)
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ConfigError(`SR_MCP_API_BASE 只允许 http/https，实际是 ${parsed.protocol}`)
  }

  const username = String(env.SR_MCP_USERNAME ?? '').trim()
  const password = String(env.SR_MCP_PASSWORD ?? '')

  if (!username || !password) {
    throw new ConfigError(
      '缺少 SR_MCP_USERNAME / SR_MCP_PASSWORD。' +
        '本服务不自建身份体系：它用一个真实的服务账号登录后端，' +
        '该账号的角色决定了它能调用哪些接口。',
    )
  }

  const timeoutMs = clamp(
    Number(env.SR_MCP_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
    MIN_TIMEOUT_MS,
    MAX_TIMEOUT_MS,
  )

  return {
    baseUrl,
    username,
    password,
    timeoutMs,
    /**
     * 写开关。默认关闭，且**必须显式打开**。
     *
     * 为什么默认关：MCP 的工具会被模型自主调用，而模型看不见「这个动作会
     * 真的发出站请求」。把唯一的写工具藏在显式开关后面，等于让「谁允许了
     * 这个能力」这件事留在部署配置里，而不是留在模型的一次猜测里。
     */
    allowWrite: TRUE_VALUES.has(String(env.SR_MCP_ALLOW_WRITE ?? '').trim().toLowerCase()),
  }
}

/** 日志一律走 stderr —— stdout 是 MCP 的 JSON-RPC 通道，写一行就会破坏协议 */
export function log(level, message, extra) {
  const line = { level, message, ...(extra ? { extra } : {}) }
  process.stderr.write(`[sec-risk-mcp] ${JSON.stringify(line)}\n`)
}
