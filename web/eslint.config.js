// ============================================================================
// ESLint 扁平配置（ESLint 10 + typescript-eslint 8 + eslint-plugin-vue 10）
//
// ── 职责边界（这是这份配置最重要的一条设计）────────────────────────────
//   类型正确性 → vue-tsc（npm run typecheck）
//   代码格式   → Prettier（.prettierrc.json）
//   明显错误   → ESLint（本文件）
//
//   三者不重复管辖同一个问题。尤其「格式」这一项必须单选一个主人：
//   eslint-plugin-vue 的 flat/recommended 带了 20+ 条纯排版规则
//   （vue/max-attributes-per-line、vue/singleline-html-element-content-newline…），
//   它们和 Prettier 对「一行放几个属性」的答案不一致，结果是
//   `npm run format` 刚改完，`npm run lint` 立刻报错 —— 互相来回改，
//   最后大家只能把 lint 关掉，反而失去意义。
//
//   所以这里铺一层 eslint-config-prettier，把全部纯格式规则关掉，
//   再在它之后按需打开少数几条（顺序不能反，否则覆盖不生效）。
//
// ── 运行环境必须显式声明 ──────────────────────────────────────────────
//   ESLint 9 起扁平配置不再从 .eslintrc 的 env 推导全局变量，
//   不声明就会把 document / console / HTMLElement 全部当成未定义变量。
//   下面按「文件实际运行在哪一侧」分别注入 globals。
// ============================================================================
import js from '@eslint/js'
import pluginVue from 'eslint-plugin-vue'
import tseslint from 'typescript-eslint'
import globals from 'globals'
import prettierConfig from 'eslint-config-prettier'

export default tseslint.config(
  {
    // 自动生成的类型声明与构建产物不做检查
    ignores: [
      'dist/',
      'node_modules/',
      'coverage/',
      '.verify/',
      'src/types/auto-imports.d.ts',
      'src/types/components.d.ts',
      // 由 docs/openapi.yaml 生成的接口类型：文件由工具全量重写，
      // 对它跑 lint 只会产生无法通过「改源码」修复的报错
      'src/api/generated/',
    ],
  },

  // ── ① 推荐集 ────────────────────────────────────────────────────────────
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...pluginVue.configs['flat/recommended'],

  // ── ② 关掉与 Prettier 冲突的全部纯格式规则 ──────────────────────────────
  //     必须是独立的一层，且排在我们自己的规则之前
  prettierConfig,

  // ── ③ 运行在 Node 侧的文件：构建配置、Vite 插件、校验脚本 ────────────────
  {
    files: ['vite.config.ts', 'plugins/**/*.ts', 'scripts/**/*.js', 'scripts/**/*.mjs'],
    languageOptions: {
      globals: { ...globals.node },
    },
  },

  // ── ④ 运行在浏览器侧的应用源码 ─────────────────────────────────────────
  {
    files: ['src/**/*'],
    languageOptions: {
      globals: { ...globals.browser },
    },
  },
  {
    // 单文件组件：<template> 由 vue-eslint-parser 解析，
    // <script lang="ts"> 内部转交给 TS 解析器
    files: ['**/*.vue'],
    languageOptions: {
      parserOptions: {
        parser: tseslint.parser,
        extraFileExtensions: ['.vue'],
        sourceType: 'module',
      },
    },
  },
  {
    files: ['src/**/*.ts', 'src/**/*.vue'],
    rules: {
      // ⚠️ TS 文件关掉 no-undef —— 这是 typescript-eslint 的官方建议，不是偷懒：
      //    TS 自己就会报「找不到名称」，而且它能正确理解**只在类型空间存在**的
      //    全局名（如 env.d.ts 里 declare 的 __APP_VERSION__、纯 interface）。
      //    ESLint 的 no-undef 只认运行时的值，对这类名字会大面积误报。
      'no-undef': 'off',
    },
  },

  // ── ⑤ 项目自定义规则（最后铺，优先级最高）──────────────────────────────
  {
    rules: {
      // --- Vue：只留 Prettier 不管、但值得统一的几条 ---
      // 组件名强制多词，避免与原生 HTML 元素冲突（App/窗口级入口除外）
      'vue/multi-word-component-names': 'error',
      // 属性书写顺序按官方分类，纯语义规则，Prettier 不介入
      'vue/attributes-order': 'warn',
      // props 默认 camelCase，模板中写 kebab-case
      'vue/attribute-hyphenation': 'error',
      // 自闭合：取值刻意与 Prettier 的输出保持一致 ——
      //   void（img/br/input）永远自闭合，普通元素不自闭合，组件自闭合。
      //   这样 eslint --fix 和 prettier --write 不会互相推翻。
      'vue/html-self-closing': [
        'error',
        { html: { void: 'always', normal: 'never', component: 'always' } },
      ],

      // --- TypeScript ---
      // 下划线开头的参数视为有意省略（常见于回调占位）
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // 与后端契约对齐的接口字段常是 snake_case，这条规则只会添乱
      '@typescript-eslint/naming-convention': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',

      // --- 通用 ---
      eqeqeq: ['error', 'smart'],
      'prefer-const': 'error',
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'no-debugger': 'error',
    },
  },

  // ── ⑥ 必须排在最后：命令行工具豁免 ─────────────────────────────────────
  //     ESLint 的扁平配置是「后面的同名规则覆盖前面的」，上面 ⑤ 是无 files
  //     的通配块且排在后面，会把任何早于它声明的豁免重新盖掉 ——
  //     这就是为什么这条明明很简单的豁免要专门放到文件最末尾。
  {
    files: ['scripts/**/*.js', 'scripts/**/*.mjs', 'vite.config.ts', 'plugins/**/*.ts'],
    rules: {
      // 这些脚本靠 stdout 向人和 CI 汇报结果，console.log 是它们的正经输出通道
      'no-console': 'off',
    },
  },
)
