<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div class="app-page flex h-full flex-col items-center justify-center">
    <el-result icon="error" title="403" sub-title="当前账号没有访问该页面的权限">
      <template #extra>
        <p class="mb-4 text-sm text-gray-500">如需访问，请联系管理员为你的账号分配相应角色。</p>
        <el-button type="primary" @click="router.replace('/')">返回首页</el-button>
      </template>
    </el-result>
  </div>
</template>
