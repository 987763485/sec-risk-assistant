#!/usr/bin/env node
/**
 * MCP Server 的 stdio 冒烟测试。
 *
 * 分三层：
 *
 *   ① **协议层**（默认执行，不需要后端、不需要账号）
 *      真起一个子进程当 MCP Server，走完整的 initialize / tools/list 握手，
 *      断言工具清单、只读标注、以及写开关的开关语义。
 *      这一层之所以必须存在：MCP 的故障模式里最贵的一类是**清单悄悄变了**
 *      （少一个工具、写工具默认被暴露出去），而它不会让任何已有功能报错。
 *
 *   ② **配置层**（默认执行）
 *      直接 import `loadConfig` 做矩阵断言。它是纯函数（env 从参数注入），
 *      没必要为了测它反复起进程 —— 每次起进程约 10 秒，而这里要覆盖
 *      十几组取值。真起进程只保留一个用例：**配置缺失时进程以非零码退出、
 *      且把原因写给 stderr**，那是「快速失败」这条设计承诺的落点。
 *
 *   ③ **调用层**（设置 SR_MCP_LIVE=1 才执行）
 *      真登录、真调一次 get_dashboard_summary，并断言错误以「工具级错误」
 *      而不是协议异常的形式返回。需要后端在跑且账号可用。
 *
 * 为什么不用「import 一下工具定义数组做断言」这种轻量做法：
 * 那样测的是「我写的数组长什么样」，而不是「客户端实际收到什么」——
 * 注册阶段的过滤、SDK 对 schema 的规范化、annotations 的透传全都测不到。
 */

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

import { ConfigError, loadConfig } from '../src/config.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ENTRY = path.join(HERE, '..', 'src', 'index.js')

const EXPECTED_READ_TOOLS = [
  'get_dashboard_summary',
  'list_assets',
  'list_vulnerabilities',
  'get_vulnerability',
  'list_assessments',
  'list_risk_items',
  'list_remediations',
  'list_integrations',
]
const WRITE_TOOL = 'fetch_vuln_intel'

/** 子进程启动护栏。⚠️ 是**超时护栏**而不是性能阈值：本机实测冷启动约 10 秒
 *  （SDK 的模块图很大，且这里的文件 I/O 慢），给足余量避免把「机器慢」
 *  误报成「程序挂了」——那类假红会让人开始无视这个脚本。 */
const SPAWN_GUARD_MS = 60000

let passed = 0
let failed = 0

function check(ok, label, detail) {
  if (ok) {
    passed++
    console.log(`  ✔ ${label}`)
  } else {
    failed++
    console.log(`  ✘ ${label}${detail ? ` — ${detail}` : ''}`)
  }
}

function section(title) {
  console.log(`\n── ${title} ──`)
}

/** 起一个子进程当服务端，返回可直接连接的 transport */
function spawnTransport(extraEnv = {}) {
  return new StdioClientTransport({
    command: process.execPath,
    args: [ENTRY],
    env: {
      ...process.env,
      SR_MCP_USERNAME: 'smoke-user',
      SR_MCP_PASSWORD: 'smoke-pass',
      // 指向一个必然连不上的地址：本层的断言全部与后端无关，
      // 让启动自检快速失败可以避免在真实网络超时上磨时间
      SR_MCP_API_BASE: 'http://127.0.0.1:1',
      SR_MCP_ALLOW_WRITE: '',
      ...extraEnv,
    },
    stderr: 'ignore',
  })
}

async function connectWith(extraEnv = {}) {
  const client = new Client({ name: 'sec-risk-mcp-smoke', version: '0.0.0' })
  await client.connect(spawnTransport(extraEnv))
  return client
}

// ---------------------------------------------------------------- ① 协议层

async function protocolLayer() {
  section('① 工具清单由写开关决定')

  const client = await connectWith()
  const info = client.getServerVersion()
  check(
    info?.name === 'sec-risk-assistant',
    `服务端标识为 sec-risk-assistant`,
    `实际 ${info?.name}`,
  )

  const { tools } = await client.listTools()
  const names = tools.map((t) => t.name)

  check(
    names.length === EXPECTED_READ_TOOLS.length,
    `默认暴露 ${EXPECTED_READ_TOOLS.length} 个工具`,
    `实际 ${names.length}：${names.join(', ')}`,
  )

  const missing = EXPECTED_READ_TOOLS.filter((n) => !names.includes(n))
  check(missing.length === 0, '清单包含全部预期工具', missing.join(', '))
  const extra = names.filter((n) => !EXPECTED_READ_TOOLS.includes(n))
  check(extra.length === 0, '清单没有多出预期之外的工具', extra.join(', '))
  check(!names.includes(WRITE_TOOL), `默认**不**暴露写工具 ${WRITE_TOOL}`)

  const notReadOnly = tools.filter((t) => t.annotations?.readOnlyHint !== true)
  check(
    notReadOnly.length === 0,
    '默认暴露的工具全部标注为只读',
    notReadOnly.map((t) => t.name).join(', '),
  )

  const badSchema = tools.filter((t) => !t.inputSchema || t.inputSchema.type !== 'object')
  check(badSchema.length === 0, '每个工具都带 object 类型的入参 schema')

  const undescribed = tools.filter((t) => !t.description || t.description.length < 20)
  check(undescribed.length === 0, '每个工具都有实质性的描述（模型据此决定是否调用）')

  // 写工具的入参里必须能看出「会向外发请求」，否则模型无从判断副作用
  const dashboard = tools.find((t) => t.name === 'get_dashboard_summary')
  check(
    dashboard?.inputSchema?.properties?.assessment_id !== undefined,
    '入参 schema 由 zod 正确转成了 JSON Schema',
  )

  await client.close()

  section('② SR_MCP_ALLOW_WRITE=true 时多出写工具')

  const writeClient = await connectWith({ SR_MCP_ALLOW_WRITE: 'true' })
  const writeList = (await writeClient.listTools()).tools
  const writeNames = writeList.map((t) => t.name)

  check(writeNames.includes(WRITE_TOOL), `写入开关打开后暴露 ${WRITE_TOOL}`)
  check(
    writeNames.length === EXPECTED_READ_TOOLS.length + 1,
    `工具总数变为 ${EXPECTED_READ_TOOLS.length + 1}`,
    `实际 ${writeNames.length}`,
  )

  const write = writeList.find((t) => t.name === WRITE_TOOL)
  check(write?.annotations?.readOnlyHint === false, '写工具**没有**被标注为只读')
  check(write?.annotations?.openWorldHint === true, '写工具被标注为会访问外部世界')
  check(
    write?.annotations?.destructiveHint === false,
    '写工具不是破坏性操作（它是幂等的 upsert，不删除数据）',
  )
  check(
    /真的向外发起 HTTP 请求/.test(write?.description ?? ''),
    '写工具的描述里明确写了「会真的向外发请求」',
  )

  const stillReadOnly = writeList.filter(
    (t) => t.name !== WRITE_TOOL && t.annotations?.readOnlyHint === true,
  )
  check(
    stillReadOnly.length === EXPECTED_READ_TOOLS.length,
    '其余工具仍然全部是只读',
    `实际 ${stillReadOnly.length}`,
  )

  await writeClient.close()
}

// ---------------------------------------------------------------- ② 配置层

const BASE_ENV = { SR_MCP_USERNAME: 'u', SR_MCP_PASSWORD: 'p' }

function loadWith(env) {
  return loadConfig({ ...BASE_ENV, ...env })
}

function expectsConfigError(env, label) {
  try {
    loadWith(env)
    check(false, label, '本该抛出 ConfigError，实际通过了')
  } catch (err) {
    check(err instanceof ConfigError, label, `抛出的是 ${err?.constructor?.name}`)
  }
}

function configLayer() {
  section('③ 写开关只认显式真值')

  for (const value of ['true', 'TRUE', '1', 'yes', 'on']) {
    check(loadWith({ SR_MCP_ALLOW_WRITE: value }).allowWrite === true, `写成 ${value} 时开启`)
  }
  for (const value of ['', 'false', 'no', '0', 'TRUE-ish', '2', 'y']) {
    check(loadWith({ SR_MCP_ALLOW_WRITE: value }).allowWrite === false, `写成 ${value} 时关闭`)
  }

  section('④ 地址与超时的校验')

  expectsConfigError({ SR_MCP_API_BASE: 'ftp://example.com' }, '非 http/https 协议被拒')
  expectsConfigError({ SR_MCP_API_BASE: '不是 URL' }, '不是 URL 被拒')
  expectsConfigError({ SR_MCP_USERNAME: '' }, '缺用户名被拒')
  expectsConfigError({ SR_MCP_PASSWORD: '' }, '缺密码被拒')

  const normalized = loadWith({ SR_MCP_API_BASE: 'http://127.0.0.1:8080/' })
  check(normalized.baseUrl === 'http://127.0.0.1:8080', '地址末尾斜杠被归一化掉', normalized.baseUrl)
  check(loadWith({}).baseUrl === 'http://127.0.0.1:8080', '未设置时用默认地址')

  check(loadWith({ SR_MCP_TIMEOUT_MS: '10' }).timeoutMs === 1000, '过小超时收敛到 1000ms')
  check(loadWith({ SR_MCP_TIMEOUT_MS: '999999' }).timeoutMs === 60000, '过大超时收敛到 60000ms')
  check(loadWith({ SR_MCP_TIMEOUT_MS: 'abc' }).timeoutMs === 15000, '非数字取默认 15000ms')
  check(loadWith({ SR_MCP_TIMEOUT_MS: '20000' }).timeoutMs === 20000, '合法值原样使用')

  section('⑤ 配置缺失时真进程以非零码退出，并把原因写给 stderr')

  return new Promise((resolve) => {
    const child = spawn(process.execPath, [ENTRY], {
      env: { ...process.env, SR_MCP_USERNAME: '', SR_MCP_PASSWORD: '' },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    let stderr = ''
    const timer = setTimeout(() => child.kill('SIGKILL'), SPAWN_GUARD_MS)
    child.stderr.on('data', (chunk) => (stderr += chunk))
    child.on('exit', (code) => {
      clearTimeout(timer)
      check(code !== 0, '进程以非零码退出', `实际 ${code}`)
      check(stderr.includes('SR_MCP_USERNAME'), 'stderr 里点名了缺失的环境变量')
      check(stderr.includes('配置无效'), 'stderr 里说清了这是配置问题')
      resolve()
    })
  })
}

// ---------------------------------------------------------------- ③ 调用层

async function liveLayer() {
  section('⑥ 真登录 + 真调用（SR_MCP_LIVE=1）')

  if (process.env.SR_MCP_LIVE !== '1') {
    console.log('  ⏭ 未设置 SR_MCP_LIVE=1，跳过（本层需要后端在跑）')
    return
  }

  const client = new Client({ name: 'sec-risk-mcp-smoke', version: '0.0.0' })
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [ENTRY],
      env: { ...process.env, SR_MCP_ALLOW_WRITE: '' },
      stderr: 'ignore',
    }),
  )

  const res = await client.callTool({ name: 'get_dashboard_summary', arguments: {} })
  const text = (res.content ?? []).map((c) => c.text ?? '').join('')
  check(!res.isError, 'get_dashboard_summary 调用成功', text.slice(0, 200))

  // 用一个不存在的漏洞 ID 调详情：应当拿到「工具级错误」而不是协议级异常。
  // 这是错误传播路径的断言——模型需要看到原因才能改变策略，
  // 而抛出的异常在 MCP 里只会显示成「服务器出错」。
  const miss = await client.callTool({ name: 'get_vulnerability', arguments: { id: 999999999 } })
  const missText = (miss.content ?? []).map((c) => c.text ?? '').join('')
  check(miss.isError === true, '取不存在的漏洞返回工具级错误（isError=true）')
  check(
    /NOT_FOUND|not.?found|不存在/i.test(missText),
    '错误文本带上了后端的原因',
    missText.slice(0, 200),
  )

  await client.close()
}

// ---------------------------------------------------------------- 主流程

async function main() {
  await protocolLayer()
  await configLayer()
  await liveLayer()

  console.log(`\n${failed === 0 ? '✅' : '❌'} MCP 冒烟：${passed} 通过 / ${failed} 失败`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
