<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div class="app-page flex h-full flex-col items-center justify-center gap-4">
    <el-result icon="warning" title="404" sub-title="页面不存在或已被移除">
      <template #extra>
        <el-button type="primary" @click="router.replace('/')">返回首页</el-button>
      </template>
    </el-result>
  </div>
</template>
