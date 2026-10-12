<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Lock, User } from '@element-plus/icons-vue'

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
</script>

<template>
  <div class="login-page">
    <div class="login-card">
      <div class="mb-6 text-center">
        <div class="login-mark">SR</div>
        <h1 class="mt-3 text-lg font-semibold">网络安全风险评估助手</h1>
        <p class="mt-1 text-sm text-gray-500">请使用管理员分配的账号登录</p>
      </div>

      <el-alert
        v-if="errorMessage"
        class="mb-4"
        type="error"
        :title="errorMessage"
        :closable="false"
        show-icon
      />

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        size="large"
        @submit.prevent="handleSubmit"
      >
        <el-form-item label="登录名" prop="username">
          <el-input
            v-model="form.username"
            :prefix-icon="User"
            placeholder="请输入登录名"
            autocomplete="username"
            clearable
          />
        </el-form-item>

        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            :prefix-icon="Lock"
            placeholder="请输入密码"
            autocomplete="current-password"
            show-password
            @keyup.enter="handleSubmit"
          />
        </el-form-item>

        <el-button
          class="w-full"
          type="primary"
          size="large"
          :loading="loading"
          @click="handleSubmit"
        >
          登录
        </el-button>
      </el-form>

      <p class="mt-4 text-center text-xs text-gray-400">
        连续多次登录失败会导致账号被临时锁定；忘记密码请联系管理员重置
      </p>
    </div>
  </div>
</template>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  background:
    radial-gradient(1200px 600px at 50% -10%, var(--el-color-primary-light-9), transparent),
    var(--el-bg-color-page);
}

.login-card {
  width: 100%;
  max-width: 380px;
  padding: 32px 28px;
  background-color: var(--el-bg-color);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 10px;
  box-shadow: 0 8px 30px rgb(0 0 0 / 6%);
}

.login-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background-color: var(--el-color-primary);
  color: #fff;
  font-size: 16px;
  font-weight: 700;
}
</style>
