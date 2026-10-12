#!/usr/bin/env node
/**
 * 网络安全风险评估助手 —— MCP Server（stdio）。
 *
 * ── 定位 ────────────────────────────────────────────────────────────
 *
 * 它是一个**薄客户端**，不是第二套后端：所有数据都来自主服务的 REST 接口，
 * 用一个真实的服务账号走登录流程。因此认证、授权、审计三件事完全复用
 * 既有实现 —— MCP 不是一条绕过权限的后门，越权会拿到后端真实的 403，
 * 并被记进审计日志（责任人就是配置里的服务账号）。
 *
 * 这同时决定了它的能力边界：**MCP 能做的事严格等于那个账号能做的事**。
 * 想限制模型只能读不能写，正解是把服务账号配成 auditor 这样的只读角色，
 * 而不是在这里加判断 —— 这里的判断改一行就失效，而后端的 RBAC 不会。
 *
 * ── 协议约定 ────────────────────────────────────────────────────────
 *
 * stdout 是 JSON-RPC 通道，**任何**额外的标准输出都会破坏协议；
 * 日志一律走 stderr（见 config.js 的 log()）。
 *
 * ── 环境变量 ────────────────────────────────────────────────────────
 *
 *   SR_MCP_API_BASE     后端基址，默认 http://127.0.0.1:8080
 *   SR_MCP_USERNAME     服务账号登录名（必填）
 *   SR_MCP_PASSWORD     服务账号密码（必填）
 *   SR_MCP_ALLOW_WRITE  设为 true/1/yes 才暴露 fetch_vuln_intel 写工具
 *   SR_MCP_TIMEOUT_MS   单次请求超时，默认 15000，收敛到 [1000, 60000]
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'

import { ApiClient, ApiError } from './client.js'
import { ConfigError, loadConfig, log } from './config.js'
import { buildTools } from './tools.js'

const SERVER_NAME = 'sec-risk-assistant'
const SERVER_VERSION = '0.1.0'

/** 把任意值序列化成给模型看的一段文本 */
function render(value) {
  if (value === undefined || value === null) return '（无数据）'
  return JSON.stringify(value, null, 2)
}

/**
 * 把异常转成**工具结果**而不是抛出。
 *
 * 抛出的异常在 MCP 里表现为「服务器出错」，模型拿不到原因，只能重试；
 * 而业务失败（403、404、参数不合法）是模型能理解并据此改变策略的信息，
 * 必须原样交到它手上。
 */
function failure(err, toolName) {
  if (err instanceof ApiError) {
    return {
      isError: true,
      content: [{ type: 'text', text: `${toolName} 失败：${err.toToolMessage()}` }],
    }
  }
  return {
    isError: true,
    content: [{ type: 'text', text: `${toolName} 执行出错：${err?.message ?? String(err)}` }],
  }
}

async function main() {
  let config
  try {
    config = loadConfig()
  } catch (err) {
    const reason = err instanceof ConfigError ? err.message : String(err)
    log('error', `配置无效，进程退出：${reason}`)
    // ⚠️ 用 exitCode 而不是 process.exit()：后者会**截断尚未落盘的 stderr**，
    // 于是「快速失败」这条设计只剩下一半 —— 进程确实挂了，但运维看不到原因。
    // 此刻事件循环里没有任何句柄，函数返回后进程自然以该码退出。
    process.exitCode = 1
    return
  }

  const client = new ApiClient(config)
  const tools = buildTools(config)

  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  )

  for (const tool of tools) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      async (args) => {
        try {
          const data = await tool.run(client, args ?? {})
          return { content: [{ type: 'text', text: render(data) }] }
        } catch (err) {
          // 只记「哪个工具失败」，**不记请求体与凭据**：工具入参里
          // 没有凭据，但把整个参数对象打进日志是一种会成为习惯的做法，
          // 而习惯一旦形成，未来某个带敏感入参的工具就会顺着这条路泄漏
          log('warn', `工具 ${tool.name} 调用失败：${err?.message ?? err}`)
          return failure(err, tool.name)
        }
      },
    )
  }

  const transport = new StdioServerTransport()

  await server.connect(transport)

  const readCount = tools.filter((t) => t.annotations?.readOnlyHint).length
  log('info', `已启动（stdio），暴露 ${tools.length} 个工具：只读 ${readCount} 个`, {
    baseUrl: config.baseUrl,
    writeEnabled: config.allowWrite,
  })
  if (config.allowWrite) {
    log('warn', 'SR_MCP_ALLOW_WRITE 已开启：模型可以触发对外情报拉取（fetch_vuln_intel）')
  }

  /**
   * 启动后**不阻塞地**探一次会话，只为把「账号密码错 / 后端没起」
   * 这类部署问题尽早写进 stderr。
   *
   * 刻意不 await：后端与 MCP 常常是被同一个脚本一起拉起来的，
   * 此时后端可能还没监听。为了一个诊断信息而让 MCP 握手卡住（甚至
   * 让客户端判定启动失败）是不划算的 —— 真正的调用失败会带着完整原因返回。
   */
  void (async () => {
    try {
      const me = await client.request('GET', '/api/auth/me')
      log('info', `服务账号会话就绪：${me?.username ?? config.username}`, {
        roles: (me?.roles ?? []).map((r) => r.code ?? r),
        permissions: (me?.permissions ?? []).length,
      })
      // 「初始密码未改」的账号会被后端拦在绝大多数业务接口之外
      // （AUTH_MUST_CHANGE_PASSWORD）。这是一个部署疏漏，而不是业务错误，
      // 必须在启动日志里说清楚，否则表现是一堆莫名其妙的 403。
      if (me?.must_change_password) {
        log(
          'warn',
          '服务账号仍处于「必须修改初始密码」状态：绝大多数接口会被后端拒绝。' +
            '请先在前端登录该账号完成改密，或换一个已改密的账号。',
        )
      }
    } catch (err) {
      log('warn', `启动自检未通过（首次调用工具时会重试）：${err?.message ?? err}`)
    }
  })()

  const shutdown = async (signal) => {
    log('info', `收到 ${signal}，关闭中`)
    try {
      await server.close()
    } finally {
      process.exit(0)
    }
  }
  process.on('SIGINT', () => void shutdown('SIGINT'))
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
}

main().catch((err) => {
  log('error', `启动失败：${err?.stack ?? err}`)
  // 同上：不调 process.exit()，避免截断刚写出的原因
  process.exitCode = 1
})
