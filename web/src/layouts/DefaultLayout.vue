<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Collection,
  Connection,
  Document,
  Finished,
  FolderOpened,
  Grid,
  Histogram,
  Odometer,
  SetUp,
  Share,
  User,
  Warning,
} from '@element-plus/icons-vue'
import type { Component } from 'vue'

import { buildMenuTree } from '@/router/menu'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

/**
 * 图标白名单。
 *
 * 路由 meta 里存的是图标名字符串，这里做名字 → 组件的映射。
 * 之所以不直接把组件塞进 meta：meta 需要能被序列化（面包屑、标签页
 * 之类的功能都会依赖这一点），塞组件进去会让这层能力悄悄失效。
 */
const ICONS: Record<string, Component> = {
  Odometer,
  User,
  Document,
  Grid,
  Share,
  Collection,
  FolderOpened,
  Warning,
  Histogram,
  SetUp,
  Finished,
  Connection,
}

/**
 * 菜单按权限实时重算。
 *
 * 用 computed 而不是 onMounted 里算一次：管理员在另一个标签页给当前
 * 用户加了权限时，前端刷新 /auth/me 后菜单应当立刻跟着变，
 * 而不是要用户重新登录。
 */
const menu = computed(() => buildMenuTree((code) => auth.can(code)))

const activeMenu = computed(() => (route.name ? String(route.name) : ''))

const pageTitle = computed(() => route.meta.title ?? '')

/** 侧栏折叠状态（小屏默认收起） */
const collapsed = ref(false)

onMounted(() => {
  collapsed.value = window.innerWidth < 1024
})

async function handleLogout() {
  try {
    await ElMessageBox.confirm('确定要退出登录吗？', '退出登录', {
      type: 'warning',
      confirmButtonText: '退出',
      cancelButtonText: '取消',
    })
  } catch {
    // 用户取消
    return
  }

  await auth.logout()
  ElMessage.success('已退出登录')
  await router.replace({ name: 'login' })
}

/** 命令式菜单点击：Element Plus 的 el-menu 用 index 传回路由名 */
function handleMenuSelect(name: string) {
  if (name === activeMenu.value) return
  void router.push({ name })
}
</script>

<template>
  <el-container class="h-full">
    <!-- ── 侧栏 ───────────────────────────────────────────────────── -->
    <el-aside :width="collapsed ? '64px' : '220px'" class="app-aside">
      <div class="app-brand" :class="collapsed ? 'justify-center' : ''">
        <span class="app-brand__mark">SR</span>
        <span v-if="!collapsed" class="app-brand__text">风险评估助手</span>
      </div>

      <el-menu
        :default-active="activeMenu"
        :collapse="collapsed"
        :collapse-transition="false"
        class="app-menu"
        @select="handleMenuSelect"
      >
        <el-menu-item v-for="item in menu.topLevel" :key="item.name" :index="item.name">
          <el-icon v-if="item.icon"><component :is="ICONS[item.icon]" /></el-icon>
          <template #title>{{ item.title }}</template>
        </el-menu-item>

        <el-sub-menu v-for="group in menu.groups" :key="group.title" :index="group.title">
          <template #title>
            <el-icon><Document /></el-icon>
            <span>{{ group.title }}</span>
          </template>
          <el-menu-item v-for="item in group.items" :key="item.name" :index="item.name">
            <el-icon v-if="item.icon"><component :is="ICONS[item.icon]" /></el-icon>
            <template #title>{{ item.title }}</template>
          </el-menu-item>
        </el-sub-menu>
      </el-menu>
    </el-aside>

    <el-container>
      <!-- ── 顶栏 ─────────────────────────────────────────────────── -->
      <el-header class="app-header">
        <div class="flex items-center gap-3">
          <el-button text :icon="collapsed ? undefined : undefined" @click="collapsed = !collapsed">
            {{ collapsed ? '»' : '«' }}
          </el-button>
          <h1 class="text-base font-semibold">{{ pageTitle }}</h1>
        </div>

        <div class="flex items-center gap-3">
          <!-- 角色标签由后端下发的角色码渲染，前端不硬编码角色名 -->
          <el-tag
            v-for="role in auth.roles"
            :key="role.code"
            size="small"
            type="info"
            effect="plain"
          >
            {{ role.name }}
          </el-tag>

          <el-dropdown trigger="click">
            <span class="app-user">
              <span class="app-user__avatar">{{ auth.displayName.slice(0, 1) }}</span>
              <span class="app-user__name">{{ auth.displayName }}</span>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item disabled>
                  {{ auth.user?.username }}
                </el-dropdown-item>
                <el-dropdown-item divided @click="router.push({ name: 'change-password' })">
                  修改密码
                </el-dropdown-item>
                <el-dropdown-item divided @click="handleLogout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <!-- ── 内容区 ───────────────────────────────────────────────── -->
      <el-main class="app-main">
        <RouterView v-slot="{ Component: PageComponent }">
          <component :is="PageComponent" />
        </RouterView>
      </el-main>
    </el-container>
  </el-container>
</template>

<style scoped>
.app-aside {
  display: flex;
  flex-direction: column;
  background-color: var(--el-bg-color);
  border-right: 1px solid var(--el-border-color-lighter);
  transition: width 0.2s;
  overflow: hidden;
}

.app-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 56px;
  padding: 0 16px;
  border-bottom: 1px solid var(--el-border-color-lighter);
  white-space: nowrap;
}

.app-brand__mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  flex: none;
  border-radius: 6px;
  background-color: var(--el-color-primary);
  color: #fff;
  font-size: 12px;
  font-weight: 700;
}

.app-brand__text {
  font-size: 14px;
  font-weight: 600;
}

.app-menu {
  flex: 1;
  border-right: none;
  overflow-y: auto;
}

.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  background-color: var(--el-bg-color);
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.app-user {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 6px;
}

.app-user:hover {
  background-color: var(--el-fill-color-light);
}

.app-user__avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background-color: var(--el-color-primary-light-8);
  color: var(--el-color-primary);
  font-size: 13px;
  font-weight: 600;
}

.app-user__name {
  font-size: 13px;
}

.app-main {
  padding: 0;
  background-color: var(--el-bg-color-page);
  overflow-y: auto;
}
</style>
