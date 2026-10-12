<script setup lang="ts">
/**
 * 横向条形图。
 *
 * ▍为什么用横向
 *
 * 分类名是中文词组（「服务器」「网络设备」「很高」），横向排列时标签有
 * 完整的横向空间，不必旋转 45° 或截断。竖柱图的分类标签一旦变长，
 * 要么斜排（可读性差），要么省略（丢失信息）。
 *
 * ▍为什么不用连续的色阶
 *
 * 颜色由调用方按**语义**给定（风险等级色板、严重程度色板），
 * 不按数值插值：这些分类本身就是离散的，让它看起来连续会诱导读者
 * 去比较颜色深浅的细微差别，而那是没有意义的。
 *
 * ▍高度为什么由外部定
 *
 * ECharts 需要一个确定的像素高度才能正确布局（canvas 不会自己撑开）。
 * 这里按行数算一个高度而不是写死 300px：条目从 3 个变成 8 个时，
 * 写死的高度会把柱子压成扁片。
 */
import { computed } from 'vue'
import { use } from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'

// vue-echarts 自带样式表给 `x-vue-echarts` 元素补 `display:block; width/height:100%`，
// 不引入的话自定义元素是 inline 的，图会塌成 0 高度。
//
// ⚠️ 它是**无层**样式，按 CSS 级联规则会压过 @layer 里的规则。因此高度一律
// 设在外层 `<div>`（内联 style）上，不给 <VChart> 加 `h-64` 这类工具类——
// 那会写出一条永远不生效的样式，而且看起来完全正常。
import 'vue-echarts/style.css'

// 按需注册：ECharts 全量包约 1MB，这里只引入真正用到的图表与组件
use([CanvasRenderer, BarChart, GridComponent, TooltipComponent])

export interface BarItem {
  label: string
  value: number
  color?: string
}

const props = withDefaults(
  defineProps<{
    items: BarItem[]
    /** 空态文案 */
    emptyText?: string
    /** 名称列宽度（像素） */
    labelWidth?: number
  }>(),
  { emptyText: '暂无数据', labelWidth: 72 },
)

/** 类别轴按原顺序渲染，最上面的就是调用方给的第一个 */
const categories = computed(() => props.items.map((i) => i.label))

const height = computed(() => {
  const rows = Math.max(props.items.length, 1)
  return Math.max(140, rows * 30 + 24)
})

const option = computed(() => ({
  grid: { left: props.labelWidth + 8, right: 48, top: 8, bottom: 8, containLabel: false },
  tooltip: {
    trigger: 'item',
    formatter: (params: { name: string; value: number }) => `${params.name}：${params.value}`,
  },
  xAxis: {
    type: 'value',
    // 只保留横向网格线：竖线在这个宽度下会变成视觉噪点
    splitLine: { show: true, lineStyle: { color: '#f0f0f0' } },
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { show: false },
  },
  yAxis: {
    type: 'category',
    data: categories.value,
    // 类别轴默认自下而上，反转后与阅读顺序一致（第一个在最上面）
    inverse: true,
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { color: '#606266', fontSize: 12 },
  },
  series: [
    {
      type: 'bar',
      data: props.items.map((i) => ({
        value: i.value,
        // 零值不给颜色：一根 0 长度的柱子配上高饱和色会让人以为它有量
        itemStyle: { color: i.value === 0 ? '#f0f0f0' : (i.color ?? '#79bbff') },
      })),
      barMaxWidth: 18,
      // 数值标签直接标在柱子外侧，省掉一次「对齐网格线读刻度」的动作
      label: {
        show: true,
        position: 'right',
        color: '#909399',
        fontSize: 12,
        formatter: '{c}',
      },
    },
  ],
}))
</script>

<template>
  <div v-if="items.length" :style="{ height: `${height}px` }">
    <VChart :option="option" autoresize />
  </div>
  <el-empty v-else :description="emptyText" :image-size="50" />
</template>
