package report

import (
	"fmt"
	"strings"
)

// docxRenderRequest 是 docgen 渲染接口的请求体，与
// services/docgen/Models/RenderModels.cs 中的契约一一对应。
//
// ⚠️ 字段名是 camelCase。C# 侧配了 PropertyNameCaseInsensitive，所以大小写
// 宽容，但**拼写**必须一致——拼错一个字段不报错，只是那个功能静默失效
// （比如 TableOfContents 写成 tableOfContent，收到的永远是 false，报告里
// 就是没有目录，且链路上一处报错都没有）。
//
// 改动这里必须同步三处：docs/09 §3 的字段表、docgen 的 RenderModels.cs、
// services/docgen/samples/sample-request.json。
type docxRenderRequest struct {
	Title           string        `json:"title"`
	Subtitle        string        `json:"subtitle,omitempty"`
	FooterText      string        `json:"footerText,omitempty"`
	CoverPage       bool          `json:"coverPage"`
	TableOfContents bool          `json:"tableOfContents"`
	Sections        []docxSection `json:"sections"`
}

type docxSection struct {
	Heading         string     `json:"heading"`
	Level           int        `json:"level"`
	PageBreakBefore bool       `json:"pageBreakBefore"`
	Paragraphs      []string   `json:"paragraphs"`
	Table           *docxTable `json:"table,omitempty"`
}

type docxTable struct {
	Caption         string      `json:"caption,omitempty"`
	Headers         []string    `json:"headers"`
	Rows            [][]string  `json:"rows"`
	RepeatHeaderRow bool        `json:"repeatHeaderRow"`
	Merges          []docxMerge `json:"merges,omitempty"`
}

type docxMerge struct {
	RowIndex    int    `json:"rowIndex"`
	StartColumn int    `json:"startColumn"`
	EndColumn   int    `json:"endColumn"`
	Text        string `json:"text"`
}

// 报告章节标题。
//
// 抽成常量是因为它们同时被 TOC 域收集（按大纲级别）与正文写入引用，
// 两处写死字符串迟早会不一致，而那种不一致在报告里表现为「目录里缺一章」。
const (
	headingOverview = "一、评估概述"
	headingMethod   = "二、评估方法与配置"
	headingLevels   = "三、风险等级分布"
	headingMatrix   = "四、风险矩阵"
	headingAssets   = "五、资产风险汇总"
	headingItems    = "六、风险项明细"
	headingNotes    = "附：口径说明"
)

// buildWordRequest 把 ReportData 编排成 7 个章节。
//
// 章节顺序固定，不做「按数据有无增删章节」的动态编排：
// 报告的结构稳定比「省掉一个空章节」重要——读报告的人会拿两份报告对比，
// 章节位置一变，对比就成了找不同。
func buildWordRequest(data ReportData) docxRenderRequest {
	// 除第一节外，每个一级章节另起一页。
	// 第一节不设：目录之后本来就有分页符。
	first := func(s docxSection) docxSection {
		s.PageBreakBefore = false
		return s
	}
	next := func(s docxSection) docxSection {
		s.PageBreakBefore = true
		return s
	}

	sections := []docxSection{
		first(sectionOverview(data)),
		next(sectionMethod(data)),
		next(sectionLevels(data)),
		next(sectionMatrix(data)),
		next(sectionAssets(data)),
		next(sectionItems(data)),
		next(sectionNotes(data)),
	}

	return docxRenderRequest{
		Title:           data.Title,
		Subtitle:        data.Subtitle,
		FooterText:      footerText(data),
		CoverPage:       true,
		TableOfContents: true,
		Sections:        sections,
	}
}

// ------------------------------------------------------------------ 各章节

func sectionOverview(d ReportData) docxSection {
	a := d.Assessment
	paras := []string{
		fmt.Sprintf("本报告针对「%s」的评估结果编制，评估方法为 %s（GB/T 20984 相乘法）。",
			a.Name, d.Config.Model),
		fmt.Sprintf("评估范围：%s。范围内共 %d 台资产，产出 %d 条风险项，其中最高风险值 %s（%s）。",
			scopeText(a), a.AssetsCount, a.RiskItemsCount,
			Num(d.MaxRisk), LevelLabel(levelOfMax(d))),
	}
	if strings.TrimSpace(a.Description) != "" {
		paras = append(paras, "评估说明："+a.Description)
	}

	rows := [][]string{
		{"评估名称", a.Name},
		{"评估范围", scopeText(a)},
		{"默认威胁", emptyAsDash(a.DefaultThreatName)},
		{"资产数量", Int(int64(a.AssetsCount))},
		{"风险项数量", Int(int64(a.RiskItemsCount))},
		{"最高风险值", Num(d.MaxRisk)},
		{"计算时间", emptyAsDash(a.CalculatedAt)},
		{"报告生成时间", d.GeneratedAt.Format("2006-01-02 15:04:05")},
		{"导出人", emptyAsDash(d.GeneratedBy)},
	}

	return docxSection{
		Heading:    headingOverview,
		Level:      1,
		Paragraphs: paras,
		Table: &docxTable{
			Caption:         "表 1　评估任务基本信息",
			Headers:         []string{"项目", "内容"},
			Rows:            rows,
			RepeatHeaderRow: true,
		},
	}
}

func sectionMethod(d ReportData) docxSection {
	t := d.Config.Thresholds
	return docxSection{
		Heading: headingMethod,
		Level:   1,
		Paragraphs: []string{
			"风险值按 GB/T 20984 的相乘法定量计算：R = A × T × V。其中 A 为资产价值，" +
				"由资产重要性与资产价值权重系数相乘得到；T 为威胁可能性，取威胁字典中的权重；" +
				"V 为脆弱性严重程度，取漏洞的严重程度定级。",
			fmt.Sprintf("本次评估使用的配置如下（为可复现起见，配置在计算时刻即被快照冻结，"+
				"此后修改系统配置不影响本报告的结论）。快照时间：%s。",
				d.Config.CapturedAt.Format("2006-01-02 15:04:05")),
		},
		Table: &docxTable{
			Caption: "表 2　本次评估所用配置（配置快照）",
			Headers: []string{"配置项", "取值", "说明"},
			Rows: [][]string{
				{"计算模型", d.Config.Model, "GB/T 20984 相乘法"},
				{"资产价值权重系数", Num(d.Config.AssetWeight), "A = 资产重要性 × 该系数"},
				{"「很高」下界", Int(int64(t.VeryHigh)), "R 大于等于该值判为很高"},
				{"「高」下界", Int(int64(t.High)), "用于 12 ≤ R < 20 一类的区间判定"},
				{"「中」下界", Int(int64(t.Medium)), ""},
				{"「低」下界", Int(int64(t.Low)), ""},
				{"阈值快照时间", d.Config.CapturedAt.Format("2006-01-02 15:04:05"), "四舍五入到秒"},
			},
			RepeatHeaderRow: true,
		},
	}
}

func sectionLevels(d ReportData) docxSection {
	levelRows := d.LevelRows()
	rows := make([][]string, 0, len(levelRows))
	for _, lr := range levelRows {
		rows = append(rows, []string{
			lr.Label, lr.Range, Int(int64(lr.Count)), lr.Percent + "%", lr.Action,
		})
	}

	return docxSection{
		Heading: headingLevels,
		Level:   1,
		Paragraphs: []string{
			fmt.Sprintf("全部 %d 条风险项按上述阈值判定后的分布如下。占比之和因四舍五入可能不等于 100%%。",
				d.LevelTotal()),
		},
		Table: &docxTable{
			Caption:         "表 3　风险等级分布",
			Headers:         []string{"风险等级", "风险值区间", "风险项数", "占比", "处置建议"},
			Rows:            rows,
			RepeatHeaderRow: true,
		},
	}
}

func sectionMatrix(d ReportData) docxSection {
	grid := d.GridSize()

	headers := []string{"脆弱性严重程度 ＼ 资产重要性"}
	for i := 1; i <= grid; i++ {
		headers = append(headers, Int(int64(i)))
	}

	rows := make([][]string, 0, grid+1)
	for _, mr := range d.MatrixRows() {
		row := []string{Int(int64(mr.Severity))}
		for _, cell := range mr.Counts {
			row = append(row, fmt.Sprintf("%d\n%s", cell.Count, LevelLabel(cell.Level)))
		}
		rows = append(rows, row)
	}

	// 最后一行横跨全部列，放口径说明。
	// 这里用合并单元格而不是普通的一行多列，是为了让版式上「这是一条说明
	// 而不是一行数据」一眼可辨——也是 P0 就在验证的 w:gridSpan 能力。
	noteRowIndex := len(rows)
	rows = append(rows, make([]string, len(headers)))

	return docxSection{
		Heading: headingMatrix,
		Level:   1,
		Paragraphs: []string{
			"下表是风险矩阵：横轴为资产重要性，纵轴为脆弱性严重程度，格内为「风险项数 / 该格最高等级」。",
			"格子的位置固定在 1–5 的坐标上，因此两次查看同一个评估，同一块风险始终落在同一格里。",
		},
		Table: &docxTable{
			Caption:         "表 4　风险矩阵（5 × 5）",
			Headers:         headers,
			Rows:            rows,
			RepeatHeaderRow: true,
			Merges: []docxMerge{
				{
					RowIndex:    noteRowIndex,
					StartColumn: 0,
					EndColumn:   len(headers) - 1,
					Text: fmt.Sprintf("说明：格内为风险项数与最高等级；本评估共 %d 条风险项。",
						d.Matrix.Total),
				},
			},
		},
	}
}

func sectionAssets(d ReportData) docxSection {
	rows := make([][]string, 0, len(d.Assets))
	for _, a := range d.Assets {
		rows = append(rows, []string{
			emptyAsDash(a.Name),
			emptyAsDash(a.IP),
			Int(int64(a.Importance)),
			Num(a.ValueA),
			Num(a.RiskValue),
			LevelLabel(a.RiskLevel),
			Int(int64(a.ItemsCount)),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, []string{"—", "—", "—", "—", "—", "—", "0"})
	}

	return docxSection{
		Heading: headingAssets,
		Level:   1,
		Paragraphs: []string{
			"下表按资产汇总风险。每台资产的「风险值」取其名下**最大**的风险项值，" +
				"而不是平均值——一个致命漏洞就足以决定这台机器的处置优先级，取平均会把它稀释掉。",
		},
		Table: &docxTable{
			Caption:         "表 5　资产风险汇总（按风险值降序）",
			Headers:         []string{"资产名称", "IP 地址", "重要性", "资产价值 A", "最高风险值 R", "等级", "风险项数"},
			Rows:            rows,
			RepeatHeaderRow: true,
		},
	}
}

func sectionItems(d ReportData) docxSection {
	rows := make([][]string, 0, len(d.Items))
	for _, it := range d.Items {
		rows = append(rows, []string{
			Int(int64(it.Seq)),
			assetCell(it),
			emptyAsDash(it.VulnTitle),
			emptyAsDash(it.ThreatName),
			Int(int64(it.Importance)),
			Num(it.A),
			Num(it.T),
			Num(it.V),
			Num(it.R),
			LevelLabel(it.RiskLevel),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, []string{"—", "—", "—", "—", "—", "—", "—", "—", "—", "—"})
	}

	return docxSection{
		Heading: headingItems,
		Level:   1,
		Paragraphs: []string{
			fmt.Sprintf("下表逐条列出全部 %d 条风险项。A / T / V / R 四列齐存而不是只给 "+
				"结果，是为了让读到某个数值的人能当场把它拆开核对——只给 R 的报告，"+
				"在有人质疑「为什么这台机器是 20 分」时无法自证。", len(d.Items)),
		},
		Table: &docxTable{
			Caption: "表 6　风险项明细（资产 × 漏洞）",
			Headers: []string{"序号", "资产", "漏洞", "威胁", "重要性", "A", "T", "V", "R", "等级"},
			Rows:    rows,
			// 明细表一定跨页，表头必须重复，否则翻页后无法对应列。
			RepeatHeaderRow: true,
		},
	}
}

func sectionNotes(d ReportData) docxSection {
	t := d.Config.Thresholds
	return docxSection{
		Heading: headingNotes,
		Level:   1,
		Paragraphs: []string{
			"一、风险值计算。R = A × T × V。A = 资产重要性 × 资产价值权重系数（本次为 " +
				Num(d.Config.AssetWeight) + "）；T 为威胁可能性权重；V 为漏洞严重程度档位。",
			fmt.Sprintf("二、等级判定。判定自高到低依次比较，区间为闭下界：%s 判为很高，%s 判为高，"+
				"%s 判为中，%s 判为低，%s 判为很低。因此 R 恰等于某个下界时，归入**该下界对应的档位**。",
				ThresholdRangeText(LevelVeryHigh, t), ThresholdRangeText(LevelHigh, t),
				ThresholdRangeText(LevelMedium, t), ThresholdRangeText(LevelLow, t),
				ThresholdRangeText(LevelVeryLow, t)),
			"三、可复现性。本报告的数字来自评估任务计算时刻冻结的配置快照（见第二节），" +
				"此后修改系统配置不会改变本报告的结论。若需按新配置重算，请重新执行评估。",
			"四、数据来源。资产、漏洞与威胁均来自系统内的台账数据；报告不引入任何外部数据，" +
				"也不对台账数据做修正。",
			fmt.Sprintf("五、生成信息。本报告由系统于 %s 自动导出，导出人 %s。",
				d.GeneratedAt.Format("2006-01-02 15:04:05"), emptyAsDash(d.GeneratedBy)),
		},
	}
}

// ------------------------------------------------------------------ 辅助

// footerText 生成页脚文字（页码会跟在它之后）。
//
// 页脚**不由调用方提供**而是由这里推导：Word（docgen）与 PDF（Gotenberg）
// 两套页脚机制完全不同，但页脚上那句话必须一模一样，否则同一份评估的
// docx 与 pdf 会在页脚上对不上。推导规则只有这一处，两个渲染器都调它。
//
// 用「评估名 + 生成时刻（到分钟）」而不是只放页码：报告被打印出来后
// 往往只剩纸，页脚是唯一还能说明「这是哪份评估」的地方。
func footerText(d ReportData) string {
	return fmt.Sprintf("%s　%s", d.Assessment.Name, d.GeneratedAt.Format("2006-01-02 15:04"))
}

// scopeText 把范围描述成一句人话。
//
// 只写条目数而不枚举 ID：评估范围最多 500 条，逐个列进报告会把第一页
// 变成一串数字，而这份报告是给人看的。
func scopeText(a AssessmentInfo) string {
	switch a.ScopeType {
	case "all":
		return "全部资产"
	default:
		return fmt.Sprintf("%s（共 %d 项）", ScopeTypeLabel(a.ScopeType), len(a.ScopeRef))
	}
}

// assetCell 明细表里的资产单元格：「名称（IP）」。
//
// 合并成一列而不是拆成两列：明细表已经有 10 列，A4 纸宽放不下更多；
// 而资产名称与 IP 总是同时被需要，合在一格里信息并没有丢。
func assetCell(it ItemRow) string {
	if it.AssetIP == "" {
		return emptyAsDash(it.AssetName)
	}
	return fmt.Sprintf("%s\n（%s）", emptyAsDash(it.AssetName), it.AssetIP)
}

// levelOfMax 返回 R 最大那条风险项的等级。
//
// 从已落库的明细里取，而不是拿 MaxRisk 去和阈值比一遍——那会形成
// 第二条判定路径。这里只做「找最大值」这件纯机械的事，判定仍归后端。
func levelOfMax(d ReportData) string {
	best := ""
	var maxR float64
	for _, it := range d.Items {
		if it.R > maxR || best == "" {
			maxR = it.R
			best = it.RiskLevel
		}
	}
	return best
}

// emptyAsDash 空值统一显示为「—」。
//
// 报告里留空白格会让人怀疑是渲染丢失；写「—」则明确表达「这里本来就没有」。
func emptyAsDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
