package report

import (
	"strings"
	"testing"
)

// TestBuildHTMLCarriesEveryValue HTML 里必须能找到每一条明细的四个数值。
//
// HTML 是整条 PDF 链路上唯一「人可读、可 grep」的形态，因此数值断言
// 主要放在这一层：真起一个 Gotenberg 去解 PDF 当然更接近最终产物，
// 但那属于端到端守门脚本的活；单测这里要的是快与准。
func TestBuildHTMLCarriesEveryValue(t *testing.T) {
	data := testData()
	raw, err := buildHTML(data)
	if err != nil {
		t.Fatalf("渲染 HTML 失败: %v", err)
	}
	page := string(raw)

	// 七个章节标题都出现
	for _, heading := range []string{
		"评估概述", "评估方法与配置", "风险等级分布",
		"风险矩阵", "资产风险汇总", "风险项明细", "口径说明",
	} {
		if !strings.Contains(page, heading) {
			t.Errorf("HTML 里找不到章节「%s」", heading)
		}
	}

	// 每条明细的资产名与四个数值
	for _, it := range data.Items {
		if !strings.Contains(page, it.AssetName) {
			t.Errorf("HTML 里找不到资产 %q", it.AssetName)
		}
		if !strings.Contains(page, it.VulnTitle) {
			t.Errorf("HTML 里找不到漏洞 %q", it.VulnTitle)
		}
	}

	// 最高风险值必须以与接口一致的写法出现
	if !strings.Contains(page, Num(data.MaxRisk)) {
		t.Errorf("HTML 里找不到最高风险值 %s", Num(data.MaxRisk))
	}

	// 配置快照与阈值：报告要能自证按哪套阈值算的
	if !strings.Contains(page, "20") || !strings.Contains(page, "12") {
		t.Error("HTML 里找不到阈值（报告必须交代判定标准）")
	}
}

// TestBuildHTMLEscapesUserContent 用户录入的内容必须被转义。
//
// 报告是要发给外部看的文件。资产名、漏洞标题、评估描述都是用户录入的，
// 一旦直接拼进 HTML，一个叫 `</td><script>...</script>` 的资产名就能
// 改变报告结构甚至执行脚本。html/template 会做上下文感知转义，
// 这条测试的作用是**防止有人为了「顺手」把它换成字符串拼接**。
func TestBuildHTMLEscapesUserContent(t *testing.T) {
	data := testData()
	data.Assessment.Name = `<script>alert('xss')</script>`
	data.Assessment.Description = `<img src=x onerror=alert(1)>`
	data.Items[0].VulnTitle = `"><script>alert(2)</script>`

	raw, err := buildHTML(data)
	if err != nil {
		t.Fatalf("渲染 HTML 失败: %v", err)
	}
	page := string(raw)

	if strings.Contains(page, "<script>") {
		t.Error("HTML 里出现了未转义的 <script> —— 用户内容必须转义")
	}
	if strings.Contains(page, "onerror=alert(1)>") {
		t.Error("HTML 里出现了未转义的事件处理器")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("预期中的转义形式 &lt;script&gt; 没有出现（说明内容可能被丢弃而不是转义）")
	}
	// 转义之后原文仍应可辨识（不是被整段吞掉）
	if !strings.Contains(page, "alert") {
		t.Error("转义后原内容被整段丢弃：用户会看到空白而不是他输入的文字")
	}
}

// TestPDFFooterHasPageNumber 页脚模板必须带 Gotenberg 的页码占位类名。
//
// Chromium 不支持 CSS Paged Media 的 @bottom-center，页码只能由 Gotenberg
// 注入 —— 它按 class 名找 pageNumber / totalPages 两个元素。类名写错
// 不会报错，页面上只是永远显示 0 或者空白。
func TestPDFFooterHasPageNumber(t *testing.T) {
	footer := pdfFooterHTML(testData())

	if !strings.Contains(footer, `class="pageNumber"`) {
		t.Error("页脚缺少 pageNumber 占位（Gotenberg 按 class 名注入页码）")
	}
	if !strings.Contains(footer, `class="totalPages"`) {
		t.Error("页脚缺少 totalPages 占位")
	}
	if !strings.Contains(footer, "E2E 评估（P5 报告）") {
		t.Error("页脚应带上评估名，方便单独打开某一页时知道它出自哪份报告")
	}
}

// TestPDFFooterEscapesName 页脚是手工拼的 HTML，必须显式转义。
//
// 与主模板不同：主模板走 html/template 有自动转义，页脚这里是
// 字符串拼接，忘了转义就是一个真实的注入面。
func TestPDFFooterEscapesName(t *testing.T) {
	data := testData()
	data.Assessment.Name = `<b>粗体</b>`

	footer := pdfFooterHTML(data)
	if strings.Contains(footer, "<b>粗体</b>") {
		t.Error("页脚里的评估名未被转义")
	}
	if !strings.Contains(footer, "&lt;b&gt;") {
		t.Error("页脚未出现预期的转义形式")
	}
}

// TestSanitizeFileName 文件名清洗。
func TestSanitizeFileName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"E2E 评估（P5 报告）", "E2E 评估_P5 报告_"},
		{`bad/name\with:illegal"chars`, "bad_name_with_illegal_chars"},
		{"", "评估报告"},
		{"...", "评估报告"},
		{"正常名称", "正常名称"},
	}
	for _, c := range cases {
		if got := SanitizeFileName(c.in); got != c.want {
			t.Errorf("SanitizeFileName(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}

	// 超长名要按**字符**截断（按字节截会把一个汉字劈成半个）
	long := strings.Repeat("很长的评估名称", 30)
	got := SanitizeFileName(long)
	if len([]rune(got)) > fileNameMaxRunes {
		t.Errorf("截断后仍有 %d 个字符，上限 %d", len([]rune(got)), fileNameMaxRunes)
	}
	for _, r := range got {
		if r == '\uFFFD' {
			t.Fatal("截断产生了无效字符：说明是按字节截断的")
		}
	}
}
