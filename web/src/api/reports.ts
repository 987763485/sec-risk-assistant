import type { ReportFormat } from './endpoints'
import { api } from './http'
import { filenameFromDisposition, type DownloadedFile } from '../utils/download'

/**
 * 报告导出（P5）。
 *
 * ▍为什么是 POST
 *
 * 导出和「下载导入模板」看起来是一回事（都是拿一个文件），但契约把它定成
 * POST，原因是**导出必须留下审计**：`report.export` 要记录谁在什么时候
 * 导出了哪一份评估。GET 做不到这一点——它会被浏览器预取、被 `<a href>`
 * 直接触发、被粘贴进地址栏，审计里因此会出现用户从未做过的操作；而 GET
 * 也没有 CSRF 防护，等于任何人构造一个链接就能让别人替他导出一份报告。
 *
 * 代价是前端不能再用 `<a href>` 或 `window.open`：只能走 XHR 把字节读出来
 * 自己存盘。这正是 `saveBlob` 存在的原因。
 */

/**
 * 导出请求的超时上限。
 *
 * ⚠️ 必须显式放宽，**不能沿用 axios 实例上的 30s 默认值**。三条链路的
 * 耗时上限差了一个数量级：
 *
 *   excel → 进程内生成，毫秒级
 *   word  → docgen，单次 30s，网络类失败会重试一次
 *   pdf   → 本进程渲染 HTML + Gotenberg(Chromium) 转换，单次 60s，同样重试
 *
 * 服务端为此把 `server.write_timeout` 定成 180s，nginx 侧是 200s。
 * 前端取 210s，意图是**让服务端先决定这次导出的结局**：如果前端比服务端
 * 先放弃，用户看到的是「请求超时」，而真正的原因（503 上游不可用 /
 * 409 尚未计算）其实已经躺在服务端那份因为客户端断开而送不出去的响应里了。
 */
const EXPORT_TIMEOUT_MS = 210_000

/** 格式元信息。下拉选项与兜底文件名共用一份，避免两处各写一遍中文名。 */
export interface ReportFormatOption {
  value: ReportFormat
  /** 下拉里显示的格式名 */
  label: string
  /** 扩展名（不含点） */
  ext: string
}

export const REPORT_FORMAT_OPTIONS: readonly ReportFormatOption[] = [
  { value: 'word', label: 'Word 文档', ext: 'docx' },
  { value: 'excel', label: 'Excel 表格', ext: 'xlsx' },
  { value: 'pdf', label: 'PDF 文件', ext: 'pdf' },
]

/**
 * 导出报告文件。
 *
 * 与其它 api 方法的区别：返回值里带**文件名**。它来自响应头
 * `Content-Disposition`，所以这里用 `api.download` 拿完整响应，
 * 而不是 `api.post`（后者只交回拆完信封的 data）。
 *
 * 失败时抛 `HttpError`，code / message 是后端的原话：
 *   - 409 `REPORT_NOT_CALCULATED` —— 任务还没计算过
 *   - 503 `REPORT_RENDER_FAILED`  —— 渲染服务不可用（word / pdf 才有）
 * 二进制响应里的 JSON 错误信封不用在这里处理，client.ts 的响应拦截器
 * 已经统一读回来了（`parseBlobEnvelope`）。
 *
 * @param assessmentName 仅在响应头缺失时用于兜底文件名，见 `fallbackFileName`
 */
export async function exportReport(
  assessmentId: number,
  format: ReportFormat,
  assessmentName: string,
): Promise<DownloadedFile> {
  const res = await api.download<Blob>({
    url: '/reports/export',
    method: 'post',
    data: { assessment_id: assessmentId, format },
    responseType: 'blob',
    timeout: EXPORT_TIMEOUT_MS,
    // 服务端不做内容协商（它按 format 直接回字节），这里声明 `*/*` 只是把
    // 「我要的是二进制」写清楚，免得中间层按 application/json 去处理它。
    // 注意不能靠 client.ts 上那个全局的 `Accept: application/json`。
    headers: { Accept: '*/*' },
  })

  return {
    blob: res.data,
    fileName:
      filenameFromDisposition(res.headers['content-disposition']) ??
      fallbackFileName(assessmentName, format),
  }
}

/**
 * 兜底文件名。
 *
 * 正常情况服务端一定给了 `Content-Disposition`（含 RFC 5987 编码的中文名
 * `{评估名}_{格式}_{yyyyMMdd-HHmm}.{ext}`），走到这个兜底说明中间有代理
 * 把响应头剥掉了。此时的首要目标不是「名字好看」，而是**别让浏览器把文件
 * 存成 "download"**。
 *
 * 因此这里**不**复刻服务端那套命名规则：复刻出来就是第二条命名路径，
 * 两边一旦分叉（时间戳差一分钟、清洗规则不一致），用户会看到同一次导出
 * 生成两个不同名字的文件，反而更难理解。
 */
function fallbackFileName(assessmentName: string, format: ReportFormat): string {
  const ext = REPORT_FORMAT_OPTIONS.find((o) => o.value === format)?.ext ?? 'bin'
  const base = assessmentName.trim() || '评估报告'
  return `${base}.${ext}`
}
