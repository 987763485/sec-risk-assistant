<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'

import { prepareCsrf } from '@/api/auth'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const formRef = ref<FormInstance>()
const form = reactive({ username: '', password: '' })
const loading = ref(false)
/** 错误提示用卡片呈现而不是 ephemeral 的 toast：登录失败的信息需要被读清楚 */
const errorMessage = ref('')

const rules: FormRules<typeof form> = {
  username: [{ required: true, message: '请输入登录名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

const remember = ref(false)

/**
 * 进入登录页就先取一次 CSRF 令牌。
 *
 * 这一步不能省：登录本身是写请求，会被 CSRF 中间件拦下。
 * 之所以放在页面挂载时而不是提交时，是为了让「网络不通」这类问题
 * 在用户开始输入前就暴露，而不是等到点了登录才失败。
 */
onMounted(async () => {
  try {
    await prepareCsrf()
  } catch {
    errorMessage.value = '无法连接到服务端，请确认后端服务已启动'
  }
})

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  errorMessage.value = ''

  try {
    await auth.login(form.username.trim(), form.password)

    // 初始密码未改时，除改密页外的接口都会被后端拦成 403，
    // 因此这里直接把人送到改密页，而不是让他先撞一次墙
    if (auth.mustChangePassword) {
      ElMessage.warning('首次登录需要先修改初始密码')
      await router.replace({ name: 'change-password' })
      return
    }

    ElMessage.success('登录成功')
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (err) {
    errorMessage.value = err instanceof HttpError ? err.message : '登录失败，请稍后重试'
  } finally {
    loading.value = false
  }
}

import BgLogin from '@/assets/images/logo-transparent.png'
</script>

<template>
  <div class="login-page">
    <div class="login-card">
      <span class="corner tl"></span>
      <span class="corner tr"></span>
      <span class="corner bl"></span>
      <span class="corner br"></span>

      <div class="brand">
        <img class="logo" :src="BgLogin" alt="网络安全风险评估助手 Logo" />
        <h1>网络安全风险评估助手</h1>
        <div class="sub">Network Security Risk Assessment Assistant</div>
      </div>

      <el-alert
        v-if="errorMessage"
        class="error-alert"
        type="error"
        :title="errorMessage"
        :closable="false"
        show-icon
      />

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        :show-message="false"
        @submit.prevent="handleSubmit"
      >
        <div class="field">
          <el-input
            v-model="form.username"
            class="tech-input"
            placeholder="请输入用户名"
            autocomplete="username"
          />
          <svg class="icon" viewBox="0 0 24 24">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>
        </div>

        <div class="field">
          <el-input
            v-model="form.password"
            class="tech-input"
            type="password"
            placeholder="请输入密码"
            autocomplete="current-password"
            show-password
            @keyup.enter="handleSubmit"
          />
          <svg class="icon" viewBox="0 0 24 24">
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </div>

        <div class="options">
          <label><input v-model="remember" type="checkbox" /> 记住密码</label>
          <a href="javascript:;">忘记密码？</a>
        </div>

        <button class="btn-login" type="submit" :disabled="loading">
          {{ loading ? "登 录 中…" : "登 录" }}
        </button>
      </el-form>

      <div class="footer">
        <div class="divider"></div>
        内部专用系统 · 请勿外传 &nbsp;|&nbsp; V1.0
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ============ 页面背景 ============ */
.login-page {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  overflow: hidden;
  background: url("@/assets/images/bg-login.png") center / cover no-repeat, #0a1628;
  font-family: "PingFang SC", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif;
}

/* 背景压暗遮罩，保证表单可读性 */
.login-page::before {
  content: "";
  position: absolute;
  inset: 0;
  background: radial-gradient(
    ellipse at center,
    rgb(6 18 38 / 25%) 0%,
    rgb(4 12 26 / 72%) 100%
  );
  pointer-events: none;
}

/* ============ 登录卡片 ============ */
.login-card {
  position: relative;
  z-index: 2;
  width: 420px;
  padding: 48px 44px 40px;
  background: rgb(10 25 47 / 55%);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
  border: 1px solid rgb(64 196 255 / 22%);
  border-radius: 16px;
  box-shadow: 0 0 0 1px rgb(0 229 255 / 6%), 0 24px 60px rgb(0 0 0 / 55%),
    inset 0 1px 0 rgb(255 255 255 / 6%);
  animation: cardIn 0.9s cubic-bezier(0.22, 1, 0.36, 1) both;
}

@keyframes cardIn {
  from {
    opacity: 0;
    transform: translateY(36px) scale(0.97);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

/* 卡片四角科技感括号装饰 */
.corner {
  position: absolute;
  width: 22px;
  height: 22px;
  border-color: #00e5ff;
  border-style: solid;
  opacity: 0.85;
  filter: drop-shadow(0 0 4px rgb(0 229 255 / 70%));
}

.corner.tl {
  top: -1px;
  left: -1px;
  border-width: 2px 0 0 2px;
  border-radius: 16px 0 0 0;
}
.corner.tr {
  top: -1px;
  right: -1px;
  border-width: 2px 2px 0 0;
  border-radius: 0 16px 0 0;
}
.corner.bl {
  bottom: -1px;
  left: -1px;
  border-width: 0 0 2px 2px;
  border-radius: 0 0 0 16px;
}
.corner.br {
  bottom: -1px;
  right: -1px;
  border-width: 0 2px 2px 0;
  border-radius: 0 0 16px 0;
}

/* ============ 品牌区 ============ */
.brand {
  margin-bottom: 36px;
  text-align: center;
}

.brand .logo {
  width: 84px;
  height: 84px;
  filter: drop-shadow(0 0 14px rgb(0 229 255 / 45%));
  animation: logoFloat 4s ease-in-out infinite;
}

@keyframes logoFloat {
  0%,
  100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-6px);
  }
}

.brand h1 {
  margin-top: 14px;
  font-size: 22px;
  font-weight: 600;
  letter-spacing: 2px;
  background: linear-gradient(92deg, #7fd8ff 0%, #00e5ff 45%, #19ffc8 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 0 0 24px rgb(0 229 255 / 25%);
}

.brand .sub {
  margin-top: 6px;
  font-size: 11px;
  letter-spacing: 3.5px;
  color: rgb(148 190 220 / 75%);
  text-transform: uppercase;
}

/* ============ 错误提示 ============ */
.error-alert {
  margin-bottom: 20px;
  border-radius: 8px;
}

/* ============ 表单字段 ============ */
.field {
  position: relative;
  margin-bottom: 22px;
}

.field .icon {
  position: absolute;
  top: 50%;
  left: 14px;
  z-index: 2;
  width: 18px;
  height: 18px;
  stroke: rgb(0 229 255 / 65%);
  fill: none;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
  transition: stroke 0.25s;
  pointer-events: none;
  transform: translateY(-50%);
}

/* 覆盖 Element Plus 输入框默认样式 */
.field :deep(.tech-input .el-input__wrapper) {
  height: 48px;
  padding: 0 16px 0 44px;
  background: rgb(6 20 38 / 60%);
  border: 1px solid rgb(64 196 255 / 18%);
  border-radius: 8px;
  box-shadow: none;
  transition: border-color 0.25s, box-shadow 0.25s, background 0.25s;
}

.field :deep(.tech-input .el-input__inner) {
  height: 46px;
  font-size: 14px;
  letter-spacing: 0.5px;
  color: #e8f4ff;
}

.field :deep(.tech-input .el-input__inner::placeholder) {
  color: rgb(148 190 220 / 45%);
}

.field :deep(.tech-input .el-input__wrapper:hover) {
  border-color: rgb(0 229 255 / 35%);
}

.field :deep(.tech-input.is-focus .el-input__wrapper),
.field :deep(.tech-input .el-input__wrapper.is-focus) {
  background: rgb(8 26 48 / 75%);
  border-color: rgb(0 229 255 / 65%);
  box-shadow: 0 0 0 3px rgb(0 229 255 / 12%), 0 0 18px rgb(0 229 255 / 18%);
}

.field:focus-within .icon {
  stroke: #00e5ff;
}

/* 密码可见切换按钮配色 */
.field :deep(.el-input__password) {
  color: rgb(148 190 220 / 60%);
}

.field :deep(.el-input__password:hover) {
  color: #00e5ff;
}

/* ============ 选项行 ============ */
.options {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 28px;
  font-size: 12.5px;
  color: rgb(148 190 220 / 80%);
}

.options label {
  display: flex;
  align-items: center;
  gap: 7px;
  cursor: pointer;
  user-select: none;
}

.options input[type="checkbox"] {
  width: 14px;
  height: 14px;
  accent-color: #00e5ff;
  cursor: pointer;
}

.options a {
  color: rgb(0 229 255 / 85%);
  text-decoration: none;
  transition: text-shadow 0.25s;
}

.options a:hover {
  text-shadow: 0 0 10px rgb(0 229 255 / 60%);
}

/* ============ 登录按钮 ============ */
.btn-login {
  position: relative;
  width: 100%;
  height: 48px;
  overflow: hidden;
  font-size: 16px;
  font-weight: 600;
  letter-spacing: 6px;
  color: #04283a;
  background: linear-gradient(92deg, #00c2ff 0%, #00e5ff 50%, #19ffc8 100%);
  background-size: 200% 100%;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: background-position 0.4s, box-shadow 0.3s, transform 0.15s;
  box-shadow: 0 6px 22px rgb(0 200 255 / 35%);
}

.btn-login:hover:not(:disabled) {
  background-position: 100% 0;
  box-shadow: 0 8px 30px rgb(0 229 255 / 55%);
}

.btn-login:active:not(:disabled) {
  transform: translateY(1px);
}

.btn-login:disabled {
  cursor: not-allowed;
  opacity: 0.75;
}

/* 按钮扫光效果 */
.btn-login::after {
  content: "";
  position: absolute;
  top: 0;
  left: -80%;
  width: 60%;
  height: 100%;
  background: linear-gradient(100deg, transparent, rgb(255 255 255 / 45%), transparent);
  transform: skewX(-20deg);
  animation: shine 3.2s ease-in-out infinite;
}

@keyframes shine {
  0%,
  55% {
    left: -80%;
  }
  100% {
    left: 130%;
  }
}

/* ============ 底部信息 ============ */
.footer {
  margin-top: 30px;
  font-size: 11px;
  letter-spacing: 1px;
  text-align: center;
  color: rgb(148 190 220 / 40%);
}

.footer .divider {
  width: 60%;
  height: 1px;
  margin: 0 auto 14px;
  background: linear-gradient(90deg, transparent, rgb(0 229 255 / 35%), transparent);
}

@media (max-width: 480px) {
  .login-card {
    width: calc(100vw - 40px);
    padding: 40px 28px 32px;
  }
}
</style>
