package report

import (
	"fmt"

	"github.com/xuri/excelize/v2"
)

// Sheet 名。中文名是刻意选择：这份文件会被直接发给业务方，
// 打开后看到「风险项明细」比看到「Sheet1」有用得多。
const (
	sheetItems  = "风险项明细"
	sheetAssets = "资产风险汇总"
	sheetMatrix = "风险矩阵"
)

// 表头样式：加粗 + 浅蓝底 + 居中 + 细边框。
//
// 与 Word 报告里表格的观感保持一致（同一个色号 F0F4FA）。
const (
	excelHeaderFill = "F0F4FA"
	excelBorderGray = "8C8C8C"
	excelTitleFont  = 14
)

// buildExcel 生成三张表的 xlsx。
//
// ▍为什么用 excelize 直接生成，而不复用 docgen
//
// docgen 只认「结构化 JSON → docx」。Excel 是完全不同的产物形态（单元格、
// 公式、sheet），把它塞进 docx 渲染器等于给一个服务加第二种职责。
// 而 excelize 是纯 Go 库、无外部进程，P2 的资产批量导入已经在用它。
//
// ▍数值必须是**数值**而不是文本
//
// 所有 A / T / V / R 都按 float64 写入，而不是格式化成字符串。
// 写字符串的话，业务方在 Excel 里连求和都做不了，而这正是他们要 Excel
// 而不是 PDF 的原因。守门脚本也因此能直接读回单元格做逐条比对。
func buildExcel(data ReportData) ([]byte, error) {
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	// 第一个 sheet 是 excelize 自动建的 Sheet1，改名复用；其余新建。
	if err := f.SetSheetName("Sheet1", sheetItems); err != nil {
		return nil, fmt.Errorf("重命名首个工作表失败: %w", err)
	}
	if _, err := f.NewSheet(sheetAssets); err != nil {
		return nil, fmt.Errorf("新建「%s」失败: %w", sheetAssets, err)
	}
	if _, err := f.NewSheet(sheetMatrix); err != nil {
		return nil, fmt.Errorf("新建「%s」失败: %w", sheetMatrix, err)
	}

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 11},
		Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{excelHeaderFill}},
		Alignment: &excelize.Alignment{
			Horizontal: "center", Vertical: "center", WrapText: true,
		},
		Border: excelBorder(),
	})
	if err != nil {
		return nil, fmt.Errorf("创建表头样式失败: %w", err)
	}

	titleStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: excelTitleFont},
	})
	if err != nil {
		return nil, fmt.Errorf("创建标题样式失败: %w", err)
	}

	if err := writeItemsSheet(f, headerStyle, titleStyle, data); err != nil {
		return nil, err
	}
	if err := writeAssetsSheet(f, headerStyle, titleStyle, data); err != nil {
		return nil, err
	}
	if err := writeMatrixSheet(f, headerStyle, titleStyle, data); err != nil {
		return nil, err
	}

	// 打开文件时停在第一张表上
	f.SetActiveSheet(0)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("写出 xlsx 失败: %w", err)
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------- 明细表

func writeItemsSheet(f *excelize.File, headerStyle, titleStyle int, data ReportData) error {
	headers := []string{"序号", "资产名称", "资产IP", "漏洞", "威胁",
		"重要性", "A", "T", "V", "R", "等级"}

	// 第 1 行：报表标题（含时间），让单独打开这张表的人也知道它出自哪次评估
	if err := setTitle(f, sheetItems, "A1", titleStyle, fmt.Sprintf(
		"%s　风险项明细（共 %d 条，生成于 %s）",
		data.Assessment.Name, len(data.Items), data.GeneratedAt.Format("2006-01-02 15:04:05"))); err != nil {
		return err
	}
	if err := setHeaderRow(f, sheetItems, 2, headers, headerStyle); err != nil {
		return err
	}

	for i, it := range data.Items {
		row := i + 3
		values := []any{
			it.Seq, it.AssetName, it.AssetIP, it.VulnTitle, it.ThreatName,
			it.Importance, it.A, it.T, it.V, it.R, LevelLabel(it.RiskLevel),
		}
		if err := setRow(f, sheetItems, row, values); err != nil {
			return err
		}
	}

	if err := setColWidths(f, sheetItems, map[string]float64{
		"A": 6, "B": 20, "C": 16, "D": 28, "E": 14,
		"F": 8, "G": 8, "H": 8, "I": 8, "J": 8, "K": 8,
	}); err != nil {
		return err
	}
	// 冻结前两行：标题 + 表头。明细表必然要滚很久，表头跟着滚就没法看了。
	return setFreeze(f, sheetItems, "A3")
}

// ---------------------------------------------------------------- 资产汇总

func writeAssetsSheet(f *excelize.File, headerStyle, titleStyle int, data ReportData) error {
	headers := []string{"资产名称", "IP 地址", "重要性",
		"资产价值 A", "最高风险值 R", "风险等级", "风险项数"}

	if err := setTitle(f, sheetAssets, "A1", titleStyle, fmt.Sprintf(
		"%s　资产风险汇总（共 %d 台，生成于 %s）",
		data.Assessment.Name, len(data.Assets), data.GeneratedAt.Format("2006-01-02 15:04:05"))); err != nil {
		return err
	}
	if err := setHeaderRow(f, sheetAssets, 2, headers, headerStyle); err != nil {
		return err
	}

	for i, a := range data.Assets {
		row := i + 3
		values := []any{
			a.Name, a.IP, a.Importance, a.ValueA, a.RiskValue,
			LevelLabel(a.RiskLevel), a.ItemsCount,
		}
		if err := setRow(f, sheetAssets, row, values); err != nil {
			return err
		}
	}

	if err := setColWidths(f, sheetAssets, map[string]float64{
		"A": 22, "B": 16, "C": 10, "D": 12, "E": 14, "F": 10, "G": 10,
	}); err != nil {
		return err
	}
	return setFreeze(f, sheetAssets, "A3")
}

// ---------------------------------------------------------------- 风险矩阵

// writeMatrixSheet 写矩阵。
//
// 拆成「风险项数」与「最高等级」两个块，而不是把两者挤在一个单元格里：
// Excel 的价值在于**能被计算和筛选**，一个 "3\n很高" 的单元格两样都做不到。
func writeMatrixSheet(f *excelize.File, headerStyle, titleStyle int, data ReportData) error {
	grid := data.Matrix.GridSize
	if grid <= 0 {
		grid = 5
	}

	if err := setTitle(f, sheetMatrix, "A1", titleStyle, fmt.Sprintf(
		"%s　风险矩阵（生成于 %s）", data.Assessment.Name,
		data.GeneratedAt.Format("2006-01-02 15:04:05"))); err != nil {
		return err
	}

	// 块 1：风险项数
	blockHeaders := []string{"脆弱性严重程度 ＼ 资产重要性"}
	for i := 1; i <= grid; i++ {
		blockHeaders = append(blockHeaders, Int(int64(i)))
	}
	if err := setHeaderRow(f, sheetMatrix, 2, blockHeaders, headerStyle); err != nil {
		return err
	}
	for sev := 1; sev <= grid; sev++ {
		values := []any{sev}
		for imp := 1; imp <= grid; imp++ {
			values = append(values, data.Matrix.Cell(uint8(imp), uint8(sev)).Count)
		}
		if err := setRow(f, sheetMatrix, sev+2, values); err != nil {
			return err
		}
	}

	// 块 2：最高等级。空一行分隔，避免两块被读成一张表。
	levelHeaderRow := grid + 4
	if err := setHeaderRow(f, sheetMatrix, levelHeaderRow, blockHeaders, headerStyle); err != nil {
		return err
	}
	for sev := 1; sev <= grid; sev++ {
		values := []any{sev}
		for imp := 1; imp <= grid; imp++ {
			values = append(values, LevelLabel(data.Matrix.Cell(uint8(imp), uint8(sev)).Level))
		}
		if err := setRow(f, sheetMatrix, levelHeaderRow+sev, values); err != nil {
			return err
		}
	}

	return setColWidths(f, sheetMatrix, map[string]float64{
		"A": 26, "B": 10, "C": 10, "D": 10, "E": 10, "F": 10,
	})
}

// ---------------------------------------------------------------- 单元格辅助

func excelBorder() []excelize.Border {
	return []excelize.Border{
		{Type: "top", Color: excelBorderGray, Style: 1},
		{Type: "bottom", Color: excelBorderGray, Style: 1},
		{Type: "left", Color: excelBorderGray, Style: 1},
		{Type: "right", Color: excelBorderGray, Style: 1},
	}
}

func setTitle(f *excelize.File, sheet, cell string, style int, text string) error {
	if err := f.SetCellValue(sheet, cell, text); err != nil {
		return fmt.Errorf("写入标题失败: %w", err)
	}
	if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
		return fmt.Errorf("设置标题样式失败: %w", err)
	}
	return nil
}

func setHeaderRow(f *excelize.File, sheet string, row int, headers []string, style int) error {
	for i, h := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, row)
		if err != nil {
			return fmt.Errorf("计算表头单元格失败: %w", err)
		}
		if err := f.SetCellValue(sheet, cell, h); err != nil {
			return fmt.Errorf("写入表头失败: %w", err)
		}
		if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
			return fmt.Errorf("设置表头样式失败: %w", err)
		}
	}
	return nil
}

// setRow 写入一行。
//
// 值按 any 传入：数值保持 float64 / uint8 / int 的原样写进单元格，
// **绝不**先转成字符串再写——那会让 Excel 把它们当文本，
// 打开后左上角一个绿色小三角，求和求不了，排序按字典序排。
func setRow(f *excelize.File, sheet string, row int, values []any) error {
	for i, v := range values {
		cell, err := excelize.CoordinatesToCellName(i+1, row)
		if err != nil {
			return fmt.Errorf("计算单元格失败: %w", err)
		}
		if err := f.SetCellValue(sheet, cell, v); err != nil {
			return fmt.Errorf("写入单元格失败: %w", err)
		}
	}
	return nil
}

func setColWidths(f *excelize.File, sheet string, widths map[string]float64) error {
	for col, w := range widths {
		if err := f.SetColWidth(sheet, col, col, w); err != nil {
			return fmt.Errorf("设置列宽失败: %w", err)
		}
	}
	return nil
}

func setFreeze(f *excelize.File, sheet, cell string) error {
	if err := f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		YSplit:      2,
		TopLeftCell: cell,
		ActivePane:  "bottomLeft",
	}); err != nil {
		return fmt.Errorf("冻结表头失败: %w", err)
	}
	return nil
}
