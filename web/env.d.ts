/// <reference types="vite/client" />

// Vite 注入的环境变量类型
interface ImportMetaEnv {
  /** 后端 API 基地址（留空则走同源 /api，由 Vite 代理或 Nginx 转发） */
  readonly VITE_API_BASE_URL?: string
  /** 开发期 Vite 代理目标 */
  readonly VITE_API_PROXY_TARGET?: string
  readonly VITE_APP_TITLE?: string
  readonly VITE_APP_VERSION?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

/** 由 vite.config.ts 的 define 注入 */
declare const __APP_VERSION__: string
