/**
 * 「下载一个文件」这件事的全部共用件：文件值对象、文件名解析、保存动作。
 *
 * 放在 utils 而不是某个 api 模块里，是因为它同时被两类调用方用到：
 * 解析响应头的是 api 层（它握着 `AxiosResponse`），触发保存的是视图层
 * （它握着 DOM）。放在任何一侧都会让另一侧产生一个莫名其妙的依赖。
 */

/** 下载到的文件：内容 + 服务端建议的文件名 */
export interface DownloadedFile {
  blob: Blob
  fileName: string
}

/**
 * 解析 Content-Disposition 里的文件名。
 *
 * 优先取 RFC 5987 的 `filename*=UTF-8''<百分号编码>`：服务端一定会给这一份，
 * 而纯 ASCII 的 `filename` 只是给老客户端的兜底（值是写死的英文名，
 * 例如 "asset-import-template.xlsx" / "security-assessment-report.docx"）。
 * 取错的话用户下载到的就是一个英文名文件，而中文名才是他认得出这份文件
 * 属于哪个任务的那条线索。
 *
 * @returns 解析不出时返回 null，由调用方回退到自己准备的默认名
 */
export function filenameFromDisposition(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw === '') return null

  const extended = /filename\*=(?:UTF-8|utf-8)''([^;]+)/.exec(raw)
  if (extended?.[1]) {
    try {
      return decodeURIComponent(extended[1])
    } catch {
      // 编码坏了就往下走纯 ASCII 分支，得到一个能用的名字总比抛错强
    }
  }

  const plain = /filename="?([^";]+)"?/.exec(raw)
  return plain?.[1]?.trim() || null
}

/**
 * 把一段内存内容保存成文件。
 *
 * 用 `URL.createObjectURL` + 一个临时的 `<a download>`，而不是
 * `window.open(url)`：后者对 Blob 不适用（它需要一个 URL），
 * 且会被弹窗拦截器盯上。
 */
export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = fileName
    // 必须挂进文档再点：Firefox 里游离节点的 click() 不会触发下载
    document.body.appendChild(link)
    link.click()
    link.remove()
  } finally {
    // 延后一拍再 revoke。立即 revoke 在部分浏览器上会取消尚未开始的下载，
    // 而不 revoke 的话每个 Blob 都会留在内存里直到页面刷新
    // （一个几 MB 的 xlsx 被反复下载几次就很明显了）。
    //
    // 用 setTimeout 而不是 requestAnimationFrame：后台标签页的 rAF
    // 会被浏览器节流甚至完全不触发，那会让 revoke 永远不执行。
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
}
