<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'

import {
  createUser,
  listRoles,
  listUsers,
  resetUserPassword,
  unlockUser,
  updateUser,
} from '@/api/users'
import type { Role, UserDetail, UserStatus } from '@/api/endpoints'
import { HttpError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime, generatePassword, isLocked } from '@/utils/format'
import { asRow, type TableRow } from '@/utils/table'

const auth = useAuthStore()

/**
 * 写操作按 user:write 权限显隐。
 *
 * ⚠️ 这只是体验层：真正的拦阻在后端每个路由的 RequirePermission 上。
 * 隐藏按钮是为了不让人点进去再吃一个 403，不是安全边界。
 */
const canWrite = computed(() => auth.can('user:write'))

/** 不允许把自己禁用 —— 与后端 guardStatusChange 的规则一致，前端先挡一层 */
const currentUserId = computed(() => auth.user?.user_id ?? 0)

// ------------------------------------------------------------------ 列表

const loading = ref(false)
const rows = ref<UserDetail[]>([])
const total = ref(0)
const roles = ref<Role[]>([])

const query = reactive({
  keyword: '',
  status: '' as UserStatus | '',
  role: '',
  page: 1,
  pageSize: 20,
})

async function load() {
  loading.value = true
  try {
    const page = await listUsers({
      page: query.page,
      pageSize: query.pageSize,
      keyword: query.keyword.trim(),
      status: query.status || undefined,
      role: query.role || undefined,
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '加载用户列表失败')
    rows.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  query.page = 1
  void load()
}

function handleReset() {
  query.keyword = ''
  query.status = ''
  query.role = ''
  query.page = 1
  void load()
}

onMounted(async () => {
  void load()
  try {
    roles.value = await listRoles()
  } catch {
    // 角色字典拿不到不影响列表浏览，静默降级为空列表
    roles.value = []
  }
})

// ------------------------------------------------------------------ 新建 / 编辑

type DialogMode = 'create' | 'edit'

const dialogVisible = ref(false)
const dialogMode = ref<DialogMode>('create')
const submitting = ref(false)
const formRef = ref<FormInstance>()
const editingId = ref(0)

const form = reactive({
  username: '',
  displayName: '',
  email: '',
  password: '',
  roles: [] as string[],
  status: 'active' as UserStatus,
})

const isCreate = computed(() => dialogMode.value === 'create')

const dialogTitle = computed(() => (isCreate.value ? '新建用户' : '编辑用户'))

const rules = computed<FormRules<typeof form>>(() => ({
  username: isCreate.value
    ? [
        { required: true, message: '请输入登录名', trigger: 'blur' },
        {
          pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$/,
          message: '3–32 位，字母或数字开头，可含下划线、点、短横线',
          trigger: 'blur',
        },
      ]
    : [],
  displayName: [{ max: 32, message: '显示名不得超过 32 个字符', trigger: 'blur' }],
  email: [{ type: 'email', message: '邮箱格式不正确', trigger: 'blur' }],
  password: isCreate.value
    ? [
        { required: true, message: '请输入初始密码', trigger: 'blur' },
        { min: 8, max: 128, message: '密码长度需为 8–128 个字符', trigger: 'blur' },
      ]
    : [],
}))

function openCreate() {
  dialogMode.value = 'create'
  editingId.value = 0
  Object.assign(form, {
    username: '',
    displayName: '',
    email: '',
    password: generatePassword(),
    roles: [],
    status: 'active' as UserStatus,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

function openEdit(row: UserDetail) {
  dialogMode.value = 'edit'
  editingId.value = row.id
  Object.assign(form, {
    username: row.username,
    displayName: row.display_name,
    email: row.email,
    password: '',
    roles: row.roles.map((r) => r.code),
    status: row.status,
  })
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    if (isCreate.value) {
      await createUser({
        username: form.username.trim(),
        display_name: form.displayName.trim() || undefined,
        email: form.email.trim() || undefined,
        password: form.password,
        roles: form.roles,
      })
      ElMessage.success('用户已创建，首次登录需修改初始密码')
    } else {
      await updateUser(editingId.value, {
        display_name: form.displayName.trim(),
        email: form.email.trim(),
        status: form.status,
        roles: form.roles,
      })
      ElMessage.success('已保存')
    }
    dialogVisible.value = false
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '保存失败')
  } finally {
    submitting.value = false
  }
}

// ------------------------------------------------------------------ 行内操作

async function toggleStatus(row: UserDetail) {
  const next: UserStatus = row.status === 'active' ? 'disabled' : 'active'
  const action = next === 'disabled' ? '禁用' : '启用'

  try {
    await ElMessageBox.confirm(
      next === 'disabled'
        ? `禁用后「${row.display_name}」将无法登录，且其当前登录状态立即失效。确定继续？`
        : `确定要启用「${row.display_name}」吗？`,
      `${action}账号`,
      { type: 'warning', confirmButtonText: action, cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  try {
    await updateUser(row.id, { status: next })
    ElMessage.success(`已${action}`)
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : `${action}失败`)
  }
}

async function handleUnlock(row: UserDetail) {
  try {
    await unlockUser(row.id)
    ElMessage.success('已解除锁定')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '解除锁定失败')
  }
}

// 重置密码对话框

const resetVisible = ref(false)
const resetTarget = ref<UserDetail | null>(null)
const resetPassword = ref('')
const resetting = ref(false)

function openReset(row: UserDetail) {
  resetTarget.value = row
  resetPassword.value = generatePassword()
  resetVisible.value = true
}

async function handleResetPassword() {
  if (!resetTarget.value) return
  if (resetPassword.value.length < 8) {
    ElMessage.warning('密码长度至少 8 位')
    return
  }

  resetting.value = true
  try {
    await resetUserPassword(resetTarget.value.id, {
      new_password: resetPassword.value,
    })
    ElMessage.success('密码已重置，该用户下次登录须改密')
    resetVisible.value = false
    await load()
  } catch (err) {
    ElMessage.error(err instanceof HttpError ? err.message : '重置密码失败')
  } finally {
    resetting.value = false
  }
}

async function copyPassword() {
  try {
    await navigator.clipboard.writeText(resetPassword.value)
    ElMessage.success('已复制到剪贴板')
  } catch {
    ElMessage.warning('复制失败，请手动选中后复制')
  }
}

// ------------------------------------------------------------------ 展示辅助

/**
 * el-table 作用域插槽给出的 row 是 `Record<PropertyKey, any>`，
 * 传给需要 UserDetail 的函数前必须经 asRow 收敛（原因见 @/utils/table）。
 */
function asUser(row: TableRow): UserDetail {
  return asRow<UserDetail>(row)
}

function statusTagType(row: UserDetail) {
  if (row.status === 'disabled') return 'info'
  if (isLocked(row.locked_until)) return 'danger'
  return 'success'
}

function statusText(row: UserDetail) {
  if (row.status === 'disabled') return '已禁用'
  if (isLocked(row.locked_until)) return '已锁定'
  return '正常'
}

/** 角色码 → 中文名，字典拿不到时回落显示原始码 */
function roleLabel(code: string) {
  return roles.value.find((r) => r.code === code)?.name ?? code
}
</script>

<template>
  <div class="app-page">
    <!-- ── 筛选 ─────────────────────────────────────────────────── -->
    <div class="app-panel mb-4">
      <div class="flex flex-wrap items-end gap-3">
        <el-input
          v-model="query.keyword"
          class="w-56"
          placeholder="搜索登录名或显示名"
          :prefix-icon="Search"
          clearable
          @keyup.enter="handleSearch"
        />

        <el-select v-model="query.status" class="w-32" placeholder="全部状态" clearable>
          <el-option label="正常" value="active" />
          <el-option label="已禁用" value="disabled" />
        </el-select>

        <el-select v-model="query.role" class="w-36" placeholder="全部角色" clearable>
          <el-option v-for="r in roles" :key="r.code" :label="r.name" :value="r.code" />
        </el-select>

        <el-button type="primary" :icon="Search" @click="handleSearch">查询</el-button>
        <el-button :icon="Refresh" @click="handleReset">重置</el-button>

        <div class="ml-auto">
          <el-button v-if="canWrite" type="primary" :icon="Plus" @click="openCreate">
            新建用户
          </el-button>
        </div>
      </div>
    </div>

    <!-- ── 列表 ─────────────────────────────────────────────────── -->
    <div class="app-panel">
      <!-- 注意：作用域插槽里的 row 类型是 Record<PropertyKey, any>，
           传给需要 UserDetail 的函数前必须经 asUser 收敛（原因见 script 中的说明） -->
      <el-table v-loading="loading" :data="rows" stripe style="width: 100%">
        <el-table-column prop="username" label="登录名" min-width="140" fixed />
        <el-table-column prop="display_name" label="显示名" min-width="120" />
        <el-table-column prop="email" label="邮箱" min-width="180">
          <template #default="{ row }">{{ row.email || '—' }}</template>
        </el-table-column>

        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusTagType(asUser(row))" size="small">{{
              statusText(asUser(row))
            }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="角色" min-width="160">
          <template #default="{ row }">
            <template v-if="row.roles.length">
              <el-tag
                v-for="r in row.roles"
                :key="r.code"
                class="mr-1"
                size="small"
                type="info"
                effect="plain"
              >
                {{ roleLabel(r.code) }}
              </el-tag>
            </template>
            <span v-else class="text-gray-400">未分配</span>
          </template>
        </el-table-column>

        <el-table-column label="待改密" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.must_change_password" type="warning" size="small">是</el-tag>
            <span v-else class="text-gray-400">否</span>
          </template>
        </el-table-column>

        <el-table-column label="最后登录" min-width="170">
          <template #default="{ row }">
            <div>{{ formatDateTime(row.last_login_at) }}</div>
            <div v-if="row.last_login_ip" class="text-xs text-gray-400">
              {{ row.last_login_ip }}
            </div>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="230" fixed="right">
          <template #default="{ row }">
            <template v-if="canWrite">
              <el-button link type="primary" size="small" @click="openEdit(asUser(row))"
                >编辑</el-button
              >
              <el-button link type="primary" size="small" @click="openReset(asUser(row))"
                >重置密码</el-button
              >

              <!-- 仅在真的处于锁定期才显示解锁，避免做出一个点了没用的按钮 -->
              <el-button
                v-if="isLocked(asUser(row).locked_until)"
                link
                type="warning"
                size="small"
                @click="handleUnlock(asUser(row))"
              >
                解锁
              </el-button>

              <el-button
                link
                :type="row.status === 'active' ? 'danger' : 'success'"
                size="small"
                :disabled="row.id === currentUserId && row.status === 'active'"
                @click="toggleStatus(asUser(row))"
              >
                {{ row.status === 'active' ? '禁用' : '启用' }}
              </el-button>
            </template>
            <span v-else class="text-xs text-gray-400">只读</span>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty description="没有符合条件的用户" />
        </template>
      </el-table>

      <div class="mt-4 flex justify-end">
        <el-pagination
          v-model:current-page="query.page"
          v-model:page-size="query.pageSize"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          background
          @current-change="load"
          @size-change="handleSearch"
        />
      </div>
    </div>

    <!-- ── 新建 / 编辑 ───────────────────────────────────────────── -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="520px" destroy-on-close>
      <el-form ref="formRef" :model="form" :rules="rules" label-width="88px">
        <el-form-item label="登录名" prop="username">
          <!-- 登录名是账号的唯一标识，创建后不可修改：改它会让审计日志里
               的历史记录无法对应到人（audit_logs 里冗余存的是登录名） -->
          <el-input
            v-model="form.username"
            :disabled="!isCreate"
            placeholder="3–32 位字母、数字、_ . -"
          />
          <span v-if="!isCreate" class="text-xs text-gray-400">登录名创建后不可修改</span>
        </el-form-item>

        <el-form-item label="显示名" prop="displayName">
          <el-input v-model="form.displayName" placeholder="留空则使用登录名" />
        </el-form-item>

        <el-form-item label="邮箱" prop="email">
          <el-input v-model="form.email" placeholder="可留空" />
        </el-form-item>

        <el-form-item v-if="isCreate" label="初始密码" prop="password">
          <div class="flex w-full gap-2">
            <el-input v-model="form.password" />
            <el-button @click="form.password = generatePassword()">重新生成</el-button>
          </div>
          <span class="text-xs text-gray-400">
            系统已生成随机初始密码，该用户首次登录时必须修改
          </span>
        </el-form-item>

        <el-form-item label="角色">
          <el-select v-model="form.roles" multiple class="w-full" placeholder="可暂不分配">
            <el-option v-for="r in roles" :key="r.code" :label="r.name" :value="r.code">
              <span>{{ r.name }}</span>
              <span class="ml-2 text-xs text-gray-400">{{ r.description }}</span>
            </el-option>
          </el-select>
        </el-form-item>

        <el-form-item v-if="!isCreate" label="状态">
          <el-radio-group v-model="form.status">
            <el-radio value="active">正常</el-radio>
            <el-radio value="disabled">禁用</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">保存</el-button>
      </template>
    </el-dialog>

    <!-- ── 重置密码 ─────────────────────────────────────────────── -->
    <el-dialog v-model="resetVisible" title="重置密码" width="460px">
      <el-alert
        class="mb-4"
        type="warning"
        :closable="false"
        show-icon
        title="重置后该用户的全部登录状态立即失效"
        description="用户下次登录必须修改此密码。请通过安全渠道告知本人。"
      />

      <el-form label-width="88px">
        <el-form-item label="用户">
          <span>{{ resetTarget?.display_name }}（{{ resetTarget?.username }}）</span>
        </el-form-item>
        <el-form-item label="新密码">
          <div class="flex w-full gap-2">
            <el-input v-model="resetPassword" />
            <el-button @click="resetPassword = generatePassword()">重新生成</el-button>
          </div>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="copyPassword">复制密码</el-button>
        <el-button @click="resetVisible = false">取消</el-button>
        <el-button type="primary" :loading="resetting" @click="handleResetPassword">
          确认重置
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
