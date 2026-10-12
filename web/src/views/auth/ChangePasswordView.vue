<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'

import { changePassword } from '@/api/auth'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()

const formRef = ref<FormInstance>()
const form = reactive({ oldPassword: '', newPassword: '', confirmPassword: '' })
const loading = ref(false)
const errorMessage = ref('')

/** 后端校验规则：8–128 个字符（按字符数而非字节数） */
const MIN_LENGTH = 8
const MAX_LENGTH = 128

/**
 * 密码强度提示。
 *
 * 只做**提示**，不做拦截：真正的规则在后端 auth.ValidatePasswordStrength。
 * 前端如果自己定一套更强的规则，就会出现「前端说不行、后端其实接受」
 * 的错配，用户被无理由地挡住。
 */
const strength = computed(() => {
  const pwd = form.newPassword
  if (!pwd) return { percent: 0, label: '', status: 'exception' as const }

  let score = 0
  if (pwd.length >= MIN_LENGTH) score += 1
  if (pwd.length >= 12) score += 1
  if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) score += 1
  if (/\d/.test(pwd)) score += 1
  if (/[^A-Za-z0-9]/.test(pwd)) score += 1

  const map = [
    { percent: 20, label: '很弱', status: 'exception' as const },
    { percent: 40, label: '较弱', status: 'exception' as const },
    { percent: 60, label: '一般', status: 'warning' as const },
    { percent: 80, label: '较强', status: 'success' as const },
    { percent: 100, label: '很强', status: 'success' as const },
  ]
  return map[Math.min(score, map.length) - 1] ?? map[0]
})

const rules: FormRules<typeof form> = {
  oldPassword: [{ required: true, message: '请输入原密码', trigger: 'blur' }],
  newPassword: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    {
      min: MIN_LENGTH,
      max: MAX_LENGTH,
      message: `新密码长度需为 ${MIN_LENGTH}–${MAX_LENGTH} 个字符`,
      trigger: 'blur',
    },
    {
      validator: (_rule, value: string, callback) => {
        if (value && value === form.oldPassword) {
          callback(new Error('新密码不能与原密码相同'))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
  confirmPassword: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (value !== form.newPassword) {
          callback(new Error('两次输入的新密码不一致'))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  errorMessage.value = ''

  try {
    await changePassword({
      old_password: form.oldPassword,
      new_password: form.newPassword,
    })

    // 改密成功后后端会作废「其它设备」上的会话，但保留当前这条，
    // 因此不需要重新登录。身份里的 must_change_password 已变为 false，
    // 重新拉一次才能让守卫放行后续页面。
    await auth.restore()

    ElMessage.success('密码已修改，其它设备上的登录已失效')
    await router.replace({ path: '/' })
  } catch (err) {
    errorMessage.value = err instanceof HttpError ? err.message : '修改失败，请稍后重试'
  } finally {
    loading.value = false
  }
}

async function handleLogout() {
  await auth.logout()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <div class="cp-page">
    <div class="cp-card">
      <h1 class="text-lg font-semibold">修改密码</h1>

      <!-- 强制改密场景要明确说明「为什么不能先干别的」，否则用户只会觉得系统坏了 -->
      <el-alert
        v-if="auth.mustChangePassword"
        class="mt-4"
        type="warning"
        :closable="false"
        show-icon
        title="首次登录必须修改初始密码"
        description="初始密码由管理员设定，在修改之前无法访问其它功能。新密码请勿与初始密码相同。"
      />

      <el-alert
        v-if="errorMessage"
        class="mt-4"
        type="error"
        :title="errorMessage"
        :closable="false"
        show-icon
      />

      <el-form
        ref="formRef"
        class="mt-5"
        :model="form"
        :rules="rules"
        label-position="top"
        @submit.prevent="handleSubmit"
      >
        <el-form-item label="原密码" prop="oldPassword">
          <el-input
            v-model="form.oldPassword"
            type="password"
            placeholder="请输入当前密码"
            autocomplete="current-password"
            show-password
          />
        </el-form-item>

        <el-form-item label="新密码" prop="newPassword">
          <el-input
            v-model="form.newPassword"
            type="password"
            placeholder="8–128 个字符"
            autocomplete="new-password"
            show-password
          />
          <div v-if="form.newPassword" class="mt-2 w-full">
            <el-progress
              :percentage="strength.percent"
              :status="strength.status"
              :show-text="false"
            />
            <span class="text-xs text-gray-500">强度：{{ strength.label }}</span>
          </div>
        </el-form-item>

        <el-form-item label="确认新密码" prop="confirmPassword">
          <el-input
            v-model="form.confirmPassword"
            type="password"
            placeholder="请再次输入新密码"
            autocomplete="new-password"
            show-password
            @keyup.enter="handleSubmit"
          />
        </el-form-item>

        <div class="flex items-center gap-3">
          <el-button type="primary" :loading="loading" @click="handleSubmit"> 确认修改 </el-button>
          <!-- 强制改密时必须留一条退路，否则用户会被永久困在这一页 -->
          <el-button v-if="auth.mustChangePassword" text @click="handleLogout">
            退出登录
          </el-button>
        </div>
      </el-form>

      <p class="mt-5 text-xs text-gray-400">
        修改成功后会作废其它设备上的登录状态，当前设备保持登录。
      </p>
    </div>
  </div>
</template>

<style scoped>
.cp-page {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  padding: 24px;
  background-color: var(--el-bg-color-page);
}

.cp-card {
  width: 100%;
  max-width: 420px;
  padding: 28px;
  background-color: var(--el-bg-color);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 10px;
}
</style>
