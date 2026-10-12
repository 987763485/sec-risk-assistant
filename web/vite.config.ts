import { fileURLToPath, URL } from 'node:url'

import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

import { viteCssLayerPlugin } from './plugins/vite-plugin-css-layer.ts'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  // 本地开发时 Vite 把 /api 代理到 Go 主服务，避免跨域与 Cookie 的 SameSite 问题
  const proxyTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8080'

  return {
    plugins: [
      vue(),

      tailwindcss(),

      // Element Plus 按需引入：组件与样式一并按需加载，避免全量 340KB CSS
      AutoImport({
        imports: ['vue', 'vue-router', 'pinia'],
        resolvers: [ElementPlusResolver()],
        dts: 'src/types/auto-imports.d.ts',
        eslintrc: { enabled: false },
      }),
      Components({
        resolvers: [ElementPlusResolver({ importStyle: 'css' })],
        dts: 'src/types/components.d.ts',
        dirs: ['src/components'],
      }),

      // ⚠️ 必须放在 vue/tailwindcss 之后：它依赖 build 阶段的 generateBundle
      //    对最终 CSS 产物做注入（详见插件文件头部说明）
      viteCssLayerPlugin({
        packages: ['element-plus'],
        layerName: 'el',
        layerOrder: ['theme', 'base', 'el', 'components', 'utilities'],
      }),
    ],

    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },

    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },

    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
      // 与 dev 相同的代理。
      // 存在的意义是让**生产构建产物**能在本地按真实形态冒烟测试：
      // dev server 不做 CSS 分层处理、也不做路由分包，
      // 「本地正常、上线错乱」这类问题只有跑 dist 才暴露得出来。
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },

    build: {
      outDir: 'dist',
      assetsDir: 'assets',
      sourcemap: mode !== 'production',
      // 单个 chunk 体积告警阈值放宽（echarts 本身较大）
      chunkSizeWarningLimit: 1500,
    },

    define: {
      __APP_VERSION__: JSON.stringify(env.APP_VERSION || '0.1.0'),
    },
  }
})
