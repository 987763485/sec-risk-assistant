<script setup lang="ts">
/**
 * 环形图（甜甜圈）。
 *
 * 用途是看**构成比例**：整改单在五个状态上怎么分布。
 * 选环图而不是饼图，是因为中间那块空白正好放总数——这类图最常见的问题
 * 就是「读者分不清整体是多少」，把总数写在洞里比写在标题里更直接。
 *
 * ⚠️ 只在分类数少（≤ 6）且各分类互斥时用它。分类多或需要比较精确数值时
 * 用条形图（见 HBarChart）——环图的相邻扇区角度很难肉眼比较。
 */
import { computed } from 'vue'
import { use } from 'echarts/core'
import { PieChart } from 'echarts/charts'
import { LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'

use([CanvasRenderer, PieChart, LegendComponent, TooltipComponent])

const props = withDefaults(
  defineProps<{
    items: { label: string; value: number; color?: string }[]
    /** 环中心的文字（通常是总数） */
    centerLabel?: string
    emptyText?: string
    height?: number
  }>(),
  { centerLabel: '', emptyText: '暂无数据', height: 260 },
)

const total = computed(() => props.items.reduce((sum, i) => sum + i.value, 0))

const option = computed(() => ({
  tooltip: {
    trigger: 'item',
    formatter: (params: { name: string; value: number; percent: number }) =>
      `${params.name}：${params.value}（${params.percent}%）`,
  },
  legend: {
    bottom: 0,
    itemWidth: 10,
    itemHeight: 10,
    textStyle: { color: '#606266', fontSize: 12 },
  },
  series: [
    {
      type: 'pie',
      // 环形：内半径 55% 留出中心文字的位置
      radius: ['55%', '78%'],
      center: ['50%', '44%'],
      avoidLabelOverlap: true,
      // 扇区不设间隙描边之外的装饰：它在数据为 0 时会把整圈画成细线
      itemStyle: { borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      labelLine: { show: false },
      data: props.items.map((i) => ({
        name: i.label,
        value: i.value,
        itemStyle: { color: i.value === 0 ? '#f0f0f0' : (i.color ?? '#79bbff') },
      })),
    },
  ],
}))
</script>

<template>
  <div v-if="items.length && total > 0" class="relative" :style="{ height: `${height}px` }">
    <VChart :option="option" autoresize />
    <!-- 中心文字用普通 DOM 而不是 ECharts 的 graphic：
         它是 HTML 的排版问题（字体、字重、居中），用 DOM 一次说清，
         用 graphic 还要自己算像素位置。 -->
    <div
      class="pointer-events-none absolute left-1/2 -translate-x-1/2 text-center"
      style="top: 34%"
    >
      <div class="text-2xl font-semibold">{{ total }}</div>
      <div class="text-xs text-gray-500">{{ centerLabel }}</div>
    </div>
  </div>
  <el-empty v-else :description="emptyText" :image-size="50" />
</template>
