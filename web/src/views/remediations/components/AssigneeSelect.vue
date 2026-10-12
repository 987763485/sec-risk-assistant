<script setup lang="ts">
/**
 * 负责人选择器。
 *
 * ▍为什么单独抽一个组件
 *
 * 「分派整改负责人」需要用户清单，而读取用户清单要 `user:read` ——
 * 内置角色里只有管理员有。整改单的写入权限（`remediation:write`）
 * 却同时给了评估员。也就是说：**评估员能建单、能改单，但拉不到用户清单**。
 *
 * 这不是缺陷，是权限模型里两组权限刻意解耦的结果。前端能做的是
 * 把这条限制**明说**出来（控件禁用 + 一行提示），而不是让一个空下拉框
 * 在那里让人以为是没数据。真要放开，那是改角色定义的事，不该在页面里
 * 用「多试一个接口」来绕过。
 */
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import { HttpError } from '@/api/http'
import { listUsers } from '@/api/users'
import { useAuthStore } from '@/stores/auth'

const model = defineModel<number | null>({ default: null })

defineProps<{ placeholder?: string }>()

const auth = useAuthStore()

/** 能否读取用户清单。不能时控件禁用，并在下方说明原因 */
const canReadUsers = computed(() => auth.can('user:read'))

const loading = ref(false)
const options = ref<{ id: number; label: string }[]>([])

async function load() {
  if (!canReadUsers.value) return
  loading.value = true
  try {
    // 单页 100 条：这是给「分派」用的选择器，不是用户管理页。
    // 超过 100 人的部署需要远程搜索，那时再改（现在的取舍是少一个接口）。
    const page = await listUsers({ page: 1, pageSize: 100 })
    options.value = page.items.map((u) => ({
      id: u.id,
      label: u.display_name || u.username,
    }))
  } catch (err) {
    // 拉不到清单不阻断整改单的其它操作：分派是可选字段
    options.value = []
    if (err instanceof HttpError) ElMessage.warning(`加载用户清单失败：${err.message}`)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
})
</script>

<template>
  <div>
    <el-select
      v-model="model"
      :placeholder="placeholder ?? '未分派'"
      :disabled="!canReadUsers"
      :loading="loading"
      clearable
      filterable
      class="w-full"
    >
      <el-option v-for="item in options" :key="item.id" :label="item.label" :value="item.id" />
    </el-select>
    <div v-if="!canReadUsers" class="mt-1 text-xs text-gray-500">
      当前账号没有「读取用户」权限，无法在此分派负责人。已分派的单子不会被改动。
    </div>
  </div>
</template>
