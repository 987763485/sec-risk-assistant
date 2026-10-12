/**
 * MCP 工具集合。
 *
 * ── 设计立场 ────────────────────────────────────────────────────────
 *
 * ① **工具是接口的投影，不是新的接口。** 每个工具的入参都直接对应后端已
 *    发布的查询参数，这里不加工、不聚合、不重命名。加一层「方便模型调用」
 *    的转换层，等于造出第二份契约：后端改了参数名，工具照旧收旧参数，
 *    表现为「某个筛选条件永远不生效」。
 *
 * ② **默认只读。** 唯一的写工具 `fetch_vuln_intel` 必须由部署方显式开启
 *    （`SR_MCP_ALLOW_WRITE=true`）。理由是同一个能力经网页触发时，点按钮的
 *    是人；经 MCP 触发时，决定是否调用的是模型。
 *
 * ③ **不做权限判断。** 工具描述里写清「需要哪个权限码」是给人和模型看的
 *    说明，不是拦截。真正的拦截在后端，越权得到的是后端的 403 与一条审计
 *    记录——这正是「MCP 不是后门」的落点。
 */

import { z } from 'zod'

/** 分页参数在多个工具里重复出现，抽出来避免各写各的默认值 */
const page = z.number().int().min(1).optional().describe('页码，从 1 开始；越界值由后端收敛。默认 1')
const pageSize = z
  .number()
  .int()
  .min(1)
  .max(100)
  .optional()
  .describe('每页条数，上限 100，默认 20')

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }

/** 默认的 8 个只读工具 */
const READ_TOOLS = [
  {
    name: 'get_dashboard_summary',
    title: '总览统计',
    description:
      '获取首页统计：资产/漏洞/评估/整改的数量与分布，可选按评估任务过滤。' +
      '需要 assessment:read 或 asset:read 或 remediation:read 之一（三者任一即可）。',
    inputSchema: {
      assessment_id: z.number().int().positive().optional().describe('只统计该评估任务下的数据'),
    },
    async run(client, args) {
      return client.get('/api/dashboard/summary', { assessment_id: args.assessment_id })
    },
  },
  {
    name: 'list_assets',
    title: '查询资产台账',
    description: '分页查询资产。需要 asset:read。',
    inputSchema: {
      keyword: z.string().optional().describe('按名称 / IP / 负责人等模糊匹配'),
      asset_type: z.string().optional().describe('资产类型字典码，如 server / database'),
      status: z.string().optional().describe('资产状态字典码'),
      importance: z.number().int().min(1).max(5).optional().describe('重要度 1–5'),
      group_id: z.number().int().positive().optional().describe('资产组 ID'),
      include_children: z.boolean().optional().describe('是否包含子组下的资产，默认包含'),
      page,
      pageSize,
    },
    async run(client, args) {
      return client.get('/api/assets', args)
    },
  },
  {
    name: 'list_vulnerabilities',
    title: '查询漏洞清单',
    description: '分页查询漏洞。需要 vulnerability:read。',
    inputSchema: {
      keyword: z.string().optional().describe('按名称 / CVE / 主机 IP / 来源文件名 / 描述匹配'),
      severity: z.number().int().min(1).max(5).optional().describe('严重程度 1–5（1 信息，5 严重）'),
      source_file_id: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe('来源文件：0 表示只看手工录入，>0 表示只看该文件解析出的漏洞'),
      linked: z.boolean().optional().describe('只看已关联资产（true）/ 未关联（false），不传表示全部'),
      page,
      pageSize,
    },
    async run(client, args) {
      return client.get('/api/vulnerabilities', args)
    },
  },
  {
    name: 'get_vulnerability',
    title: '漏洞详情',
    description:
      '按 ID 取单个漏洞的完整信息：漏洞本体、关联资产（auto/manual 混排）、' +
      '以及已拉取的外部情报快照（`intel` 数组，可能为空）。需要 vulnerability:read。',
    inputSchema: {
      id: z.number().int().positive().describe('漏洞 ID，可由 list_vulnerabilities 得到'),
    },
    async run(client, args) {
      return client.get(`/api/vulnerabilities/${args.id}`)
    },
  },
  {
    name: 'list_assessments',
    title: '查询评估任务',
    description: '分页查询风险评估任务。需要 assessment:read。',
    inputSchema: {
      keyword: z.string().optional().describe('按任务名称 / 编号匹配'),
      status: z.string().optional().describe('任务状态，如 draft / calculated'),
      page,
      pageSize,
    },
    async run(client, args) {
      return client.get('/api/assessments', args)
    },
  },
  {
    name: 'list_risk_items',
    title: '查询风险项',
    description:
      '查询某次评估算出的风险项（含风险值、等级、命中规则快照）。' +
      '⚠️ 只有已执行过计算的评估任务才有风险项。需要 assessment:read。',
    inputSchema: {
      assessment_id: z.number().int().positive().describe('评估任务 ID'),
      importance: z.number().int().min(1).max(5).optional().describe('按资产重要度过滤'),
      severity: z.number().int().min(1).max(5).optional().describe('按漏洞严重程度过滤'),
      level: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional().describe('按风险等级过滤'),
      keyword: z.string().optional().describe('按资产 / 漏洞关键词过滤'),
      page,
      pageSize,
    },
    async run(client, args) {
      const { assessment_id: assessmentId, ...rest } = args
      return client.get(`/api/assessments/${assessmentId}/risk-items`, rest)
    },
  },
  {
    name: 'list_remediations',
    title: '查询整改单',
    description:
      '分页查询整改跟踪单。需要 remediation:read。' +
      '`overdue` 与剩余天数是**按当前日期现算**的，不是库里的字段。',
    inputSchema: {
      keyword: z.string().optional().describe('按资产 / 漏洞 / 处理人匹配'),
      status: z.string().optional().describe('整改单状态码'),
      active: z.boolean().optional().describe('只看未闭环的整改单'),
      overdue: z.boolean().optional().describe('只看已逾期的整改单'),
      assignee_id: z.number().int().positive().optional().describe('按处理人用户 ID 过滤'),
      level: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional().describe('按风险等级过滤'),
      assessment_id: z.number().int().positive().optional().describe('只看来自该评估任务的整改单'),
      page,
      pageSize,
    },
    async run(client, args) {
      return client.get('/api/remediations', args)
    },
  },
  {
    name: 'list_integrations',
    title: '查询情报源集成',
    description:
      '列出已配置的第三方情报源（NVD 等），返回配置与运行态。需要 integration:read。' +
      '⚠️ 凭据本身**不在**这里：只返回凭据所在的**环境变量名**，以及该变量当前是否已设置。' +
      '想看情报内容本身，用 get_vulnerability 读取对应漏洞的 `intel` 字段。',
    inputSchema: {},
    async run(client) {
      return client.get('/api/integrations')
    },
  },
]

/**
 * 可选的写工具。
 *
 * 它是 P7 验收标志（「配置后能拉取一条 CVE 信息」）的无界面入口：
 * 没有它，自动化流程要验证「配置是否真的能拉通」就只能开浏览器。
 */
const WRITE_TOOL = {
  name: 'fetch_vuln_intel',
  title: '拉取漏洞情报',
  description:
    '对指定漏洞触发一次外部情报拉取（默认 NVD），把结果落成快照。需要 integration:write，' +
    '并且本工具必须由部署方显式开启（SR_MCP_ALLOW_WRITE=true）。\n\n' +
    '⚠️ 三个必须知道的行为：\n' +
    '1. 它会**真的向外发起 HTTP 请求**；\n' +
    '2. 该接口恒定返回成功，成败要看结果里的 `succeeded` / `failed` / `errors`；\n' +
    '3. 它是幂等的：同一 (漏洞, 来源, CVE) 重复拉取是更新而不是新增。',
  inputSchema: {
    integration_id: z.number().int().positive().describe('情报源集成 ID，可由 list_integrations 得到'),
    vuln_id: z.number().int().positive().describe('目标漏洞 ID'),
    cve_id: z
      .string()
      .optional()
      .describe('只拉某一条 CVE；留空表示拉取该漏洞登记的全部 CVE（单次上限 5 个）'),
  },
  annotations: {
    readOnlyHint: false,
    // 不是破坏性操作，但它会写库并产生出站流量，所以两个 hint 都不能乱填
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  async run(client, args) {
    const { integration_id: integrationId, ...body } = args
    return client.request('POST', `/api/integrations/${integrationId}/fetch`, { body })
  },
}

/**
 * 生成本次进程对外暴露的工具列表。
 *
 * @param {{allowWrite: boolean}} config
 */
export function buildTools(config) {
  const read = READ_TOOLS.map((tool) => ({
    ...tool,
    annotations: READ_ONLY,
  }))
  return config.allowWrite ? [...read, WRITE_TOOL] : read
}
