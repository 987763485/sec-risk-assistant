package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html"
	"html/template"
)

// PDF 走的链路是：ReportData → HTML → Gotenberg(Chromium) → PDF。
//
// ▍为什么是 HTML 而不是直接画 PDF
//
// 直接用 Go 的 PDF 库排版，要自己处理字体嵌入、换行、分页、表格跨页——
// 那是一个需要长期维护的排版引擎。而 Chromium 已经把这些都做好了，
// 代价只是多一个容器。项目里已经在跑 Gotenberg，复用它的边际成本为零。
//
// ▍为什么用 html/template 而不是拼字符串
//
// 报告内容里含用户录入的数据（资产名称、漏洞标题、评估描述）。用
// html/template 的**上下文感知转义**，这些内容进入 HTML、属性、CSS 时
// 会被自动按各自规则转义。手工拼接的话，一个叫 `</td><script>...` 的资产名
// 就能改变报告结构——而报告是要发给外部看的文件。

//go:embed templates/report.html.tmpl
var pdfTemplateSource string

var pdfTemplate = template.Must(
	template.New("report").Funcs(template.FuncMap{
		"num":            Num,
		"levelLabel":     LevelLabel,
		"emptyAsDash":    emptyAsDash,
		"thresholdRange": ThresholdRangeText,
	}).Parse(pdfTemplateSource),
)

// pdfView 是模板的根对象。
//
// 包一层而不是直接喂 ReportData：模板里有几处需要「先算一次」的值
// （范围文本、最高等级、矩阵表头用的 1..5）。放在这里算一次，
// 比在模板里写嵌套调用清晰，也让模板保持「只取值、不推导」。
type pdfView struct {
	ReportData
	ScopeTxt string
	MaxLevel string
	Grid     []int
}

// buildHTML 渲染报告 HTML（PDF 的中间产物）。
//
// 单独暴露这一步的收益：单测可以直接断言 HTML，不必真起一个 Gotenberg。
// HTML 是整条链路上唯一「人可读、可 grep、可逐字比对数值」的形态，
// 守门脚本也因此把数值断言主要放在这一层。
func buildHTML(d ReportData) ([]byte, error) {
	view := pdfView{
		ReportData: d,
		ScopeTxt:   scopeText(d.Assessment),
		MaxLevel:   LevelLabel(levelOfMax(d)),
		Grid:       seqInt(d.GridSize()),
	}

	var buf bytes.Buffer
	if err := pdfTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("渲染报告 HTML 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// pdfFooterHTML 生成给 Gotenberg 的页脚模板。
//
// ▍为什么页脚要单独传
//
// Chromium **不支持** CSS Paged Media 的 @bottom-center（那是 WeasyPrint /
// Prince 一类引擎的能力）。页码只能由 Gotenberg 注入：它会在页脚 HTML 里
// 找 class 为 pageNumber / totalPages 的元素并填入实际值。
//
// ⚠️ 页脚文本含评估名（用户数据），这里是**手工拼 HTML**，因此必须显式
// 转义 —— 这一点与主模板不同，主模板走 html/template 有自动转义，
// 这里没有。把评估名起成 `<b>` 的话，页脚就会变成粗体。
func pdfFooterHTML(d ReportData) string {
	left := html.EscapeString(footerText(d))
	return `<html><head><meta charset="utf-8"><style>
body { font-family: "Noto Sans CJK SC", "Noto Sans CJK", sans-serif;
       font-size: 8pt; color: #666; margin: 0; }
.wrap { display: flex; justify-content: space-between; width: 100%; }
</style></head><body><div class="wrap">
<span>` + left + `</span>
<span>第 <span class="pageNumber"></span> 页 / 共 <span class="totalPages"></span> 页</span>
</div></body></html>`
}

// seqInt 生成 1..n。
func seqInt(n int) []int {
	out := make([]int, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, i)
	}
	return out
}
