package report

import (
	"fmt"
	"strings"
	"testing"
)

// TestBuildWordRequestStructure 章节编排。
//
// 报告的结构稳定性是硬要求：读报告的人会拿两份报告对比，章节位置一变，
// 对比就成了找不同。所以这里逐条钉住章节顺序、层级与分页。
func TestBuildWordRequestStructure(t *testing.T) {
	req := buildWordRequest(testData())

	if !req.CoverPage {
		t.Error("封面未开启：报告应当有独立封面页")
	}
	if !req.TableOfContents {
		t.Error("目录未开启")
	}
	if req.Title == "" {
		t.Error("报告标题为空")
	}

	want := []string{
		headingOverview, headingMethod, headingLevels,
		headingMatrix, headingAssets, headingItems, headingNotes,
	}
	got := sectionHeadings(req.Sections)
	if len(got) != len(want) {
		t.Fatalf("章节数 = %d，期望 %d（%v）", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 个章节 = %q，期望 %q", i+1, got[i], want[i])
		}
	}

	// 第一节不另起一页：目录之后本来就有分页符，多设一个会多出整页空白
	if req.Sections[0].PageBreakBefore {
		t.Error("第一节不应设置 PageBreakBefore（会与目录后的分页符叠加成空白页）")
	}
	for i := 1; i < len(req.Sections); i++ {
		if !req.Sections[i].PageBreakBefore {
			t.Errorf("第 %d 个章节 %q 应另起一页", i+1, req.Sections[i].Heading)
		}
	}

	// 所有章节都必须是 level 1：二级标题不该出现在报告骨架里，
	// 否则目录会多出几行、矩阵章节的编号也会乱。
	for _, s := range req.Sections {
		if s.Level != 1 {
			t.Errorf("章节 %q 的 level = %d，期望 1", s.Heading, s.Level)
		}
	}
}

// TestWordTablesCarryEveryItem 三张数据表的行数与内容。
//
// 重点在明细表：一条风险项对应一行。少一行意味着报告漏了数据，
// 而报告漏数据是最难被读者发现的问题——他不会去数有多少行。
func TestWordTablesCarryEveryItem(t *testing.T) {
	data := testData()
	req := buildWordRequest(data)

	// 明细表：25 条 + 10 列
	items := findSection(t, req.Sections, headingItems)
	if items.Table == nil {
		t.Fatal("明细章节没有表格")
	}
	if len(items.Table.Headers) != 10 {
		t.Errorf("明细表列数 = %d，期望 10（序号/资产/漏洞/威胁/重要性/A/T/V/R/等级）",
			len(items.Table.Headers))
	}
	if len(items.Table.Rows) != len(data.Items) {
		t.Errorf("明细表行数 = %d，期望 %d", len(items.Table.Rows), len(data.Items))
	}
	if !items.Table.RepeatHeaderRow {
		t.Error("明细表必须跨页重复表头，否则翻页后无法对应列")
	}

	// 逐条核对数值出现在对应的行里 —— 渲染器只做搬运，不产生数字，
	// 所以这里既是「搬运没丢」的断言，也顺带证明它没有偷偷改写
	for i, row := range items.Table.Rows {
		it := data.Items[i]
		if row[0] != Int(int64(it.Seq)) {
			t.Errorf("第 %d 行序号 = %q，期望 %q", i+1, row[0], Int(int64(it.Seq)))
		}
		if row[5] != Num(it.A) || row[6] != Num(it.T) || row[7] != Num(it.V) || row[8] != Num(it.R) {
			t.Errorf("第 %d 行 A/T/V/R = %v，期望 [%s %s %s %s]",
				i+1, row[5:9], Num(it.A), Num(it.T), Num(it.V), Num(it.R))
		}
		if row[9] != LevelLabel(it.RiskLevel) {
			t.Errorf("第 %d 行等级 = %q，期望 %q", i+1, row[9], LevelLabel(it.RiskLevel))
		}
	}

	// 资产汇总：5 行 × 7 列
	assets := findSection(t, req.Sections, headingAssets)
	if assets.Table == nil {
		t.Fatal("资产汇总章节没有表格")
	}
	if len(assets.Table.Rows) != len(data.Assets) {
		t.Errorf("资产汇总行数 = %d，期望 %d", len(assets.Table.Rows), len(data.Assets))
	}
	if len(assets.Table.Headers) != 7 {
		t.Errorf("资产汇总列数 = %d，期望 7", len(assets.Table.Headers))
	}

	// 等级分布：5 行（五档全覆盖，即使某档为 0 也要有一行）
	levels := findSection(t, req.Sections, headingLevels)
	if levels.Table == nil {
		t.Fatal("等级分布章节没有表格")
	}
	if len(levels.Table.Rows) != 5 {
		t.Errorf("等级分布行数 = %d，期望恒为 5（某档为 0 也要出现，否则读者以为漏了一档）",
			len(levels.Table.Rows))
	}
}

// TestWordMatrixAlways25Cells 矩阵表的形状。
//
// 矩阵的**形状**与内容同等重要：列数取决于 gridSize，少一列会让所有
// 格子的位置整体错位，而错位后的矩阵看起来依然是"一个正常的矩阵"。
func TestWordMatrixAlways25Cells(t *testing.T) {
	data := testData()
	req := buildWordRequest(data)
	mx := findSection(t, req.Sections, headingMatrix)

	if mx.Table == nil {
		t.Fatal("矩阵章节没有表格")
	}
	// 1 列行标签 + 5 列 = 6
	if len(mx.Table.Headers) != 6 {
		t.Errorf("矩阵表列数 = %d，期望 6（行标签 + 5 档重要性）", len(mx.Table.Headers))
	}
	// 5 行数据 + 1 行合并说明
	if len(mx.Table.Rows) != 6 {
		t.Errorf("矩阵表行数 = %d，期望 6（5 档严重程度 + 1 行说明）", len(mx.Table.Rows))
	}

	// 说明行必须横跨全部列
	if len(mx.Table.Merges) != 1 {
		t.Fatalf("矩阵说明行合并定义数 = %d，期望 1", len(mx.Table.Merges))
	}
	merge := mx.Table.Merges[0]
	if merge.StartColumn != 0 || merge.EndColumn != len(mx.Table.Headers)-1 {
		t.Errorf("合并区间 = [%d, %d]，期望 [0, %d]",
			merge.StartColumn, merge.EndColumn, len(mx.Table.Headers)-1)
	}
	if merge.RowIndex != len(mx.Table.Rows)-1 {
		t.Errorf("合并行号 = %d，期望最后一行 %d", merge.RowIndex, len(mx.Table.Rows)-1)
	}

	// 逐格核对计数：第 i 行对应严重程度 i+1，第 j 列对应重要性 j
	for i, row := range mx.Table.Rows[:5] {
		severity := uint8(i + 1)
		for j := 1; j <= 5; j++ {
			cell := data.Matrix.Cell(uint8(j), severity)
			want := fmt.Sprintf("%d\n%s", cell.Count, LevelLabel(cell.Level))
			if row[j] != want {
				t.Errorf("矩阵格 (重要性=%d, 严重程度=%d) = %q，期望 %q",
					j, severity, row[j], want)
			}
		}
	}
}

// TestWordLongTableHeaders 说明性文案里要交代「四列齐存」的理由。
//
// 这条断言看着琐碎，但它锁住的是一份**设计决定**：明细表带 A/T/V/R 四列
// 而不是只给 R。将来有人嫌表太宽想砍掉三列时，这个测试会失败并把他引到
// 这条注释上 —— 比写在文档里更容易被看到。
func TestWordLongTableHeaders(t *testing.T) {
	req := buildWordRequest(testData())
	items := findSection(t, req.Sections, headingItems)

	joined := strings.Join(items.Paragraphs, "")
	if !strings.Contains(joined, "四列") {
		t.Error("明细表说明应当交代 A/T/V/R 四列齐存的理由")
	}
}

// TestBuildWordRequestEmptyItems 空数据不应产生畸形表格。
//
// 「算完发现范围内一条风险项都没有」是可能发生的（全部资产都没挂漏洞）。
// 此时渲染器不能崩，也不该输出一个只有表头的表。
func TestBuildWordRequestEmptyItems(t *testing.T) {
	data := testData()
	data.Items = nil
	data.Assets = nil
	data.LevelCounts = map[string]int{}

	req := buildWordRequest(data)

	items := findSection(t, req.Sections, headingItems)
	if len(items.Table.Rows) == 0 {
		t.Error("空明细表应至少输出一行占位，否则 Word 里只有一个孤零零的表头")
	}
	assets := findSection(t, req.Sections, headingAssets)
	if len(assets.Table.Rows) == 0 {
		t.Error("空资产表应至少输出一行占位")
	}
	// 等级分布仍是 5 行
	levels := findSection(t, req.Sections, headingLevels)
	if len(levels.Table.Rows) != 5 {
		t.Errorf("空数据的等级分布行数 = %d，期望仍为 5", len(levels.Table.Rows))
	}
}

// TestNumKeepsJSONShape 数值格式必须与接口 JSON 一致。
//
// 报告里写的「20」与 export-data 里返回的 20 必须逐个字符相同，
// 否则「报告值 = 落库值」这句话在肉眼核对时就不成立。
func TestNumKeepsJSONShape(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{20, "20"},
		{1, "1"},
		{10.5, "10.5"},
		{112.5, "112.5"},
		{0.999, "0.999"},
		{19.999, "19.999"},
	}
	for _, c := range cases {
		if got := Num(c.in); got != c.want {
			t.Errorf("Num(%v) = %q，期望 %q", c.in, got, c.want)
		}
	}
}
