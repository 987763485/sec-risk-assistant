package report

import (
	"bytes"
	"testing"

	"github.com/xuri/excelize/v2"
)

// TestBuildExcelSheets 三张表都要在，且名字是中文的。
func TestBuildExcelSheets(t *testing.T) {
	raw, err := buildExcel(testData())
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}

	f, err := excelize.OpenReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("读回 xlsx 失败（文件已损坏）: %v", err)
	}
	defer func() { _ = f.Close() }()

	got := f.GetSheetList()
	want := []string{sheetItems, sheetAssets, sheetMatrix}
	if len(got) != len(want) {
		t.Fatalf("工作表 = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 张表 = %q，期望 %q", i+1, got[i], want[i])
		}
	}
}

// TestExcelItemsSheetValues 明细表的每一行都要能逐格读回。
//
// 这条测试同时守住一个容易踩的坑：**数值必须按数字写入**。
// 如果实现里先 strconv 成字符串再 SetCellValue，Excel 会把它当文本
// （打开后单元格左上角一个绿色三角，求和求不了、排序按字典序），
// 而本测试仍然读得到一模一样的字符串、照样通过。
// 所以下面额外用单元格类型做断言，见 assertCellIsNumeric 的说明。
func TestExcelItemsSheetValues(t *testing.T) {
	data := testData()
	raw, err := buildExcel(data)
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}
	f, err := excelize.OpenReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("读回 xlsx 失败: %v", err)
	}
	defer func() { _ = f.Close() }()

	rows, err := f.GetRows(sheetItems)
	if err != nil {
		t.Fatalf("读取明细表失败: %v", err)
	}
	// 1 行标题 + 1 行表头 + N 行数据
	if want := len(data.Items) + 2; len(rows) != want {
		t.Fatalf("明细表行数 = %d，期望 %d", len(rows), want)
	}

	for i, it := range data.Items {
		row := rows[i+2]
		if len(row) != 11 {
			t.Fatalf("第 %d 行有 %d 列，期望 11", i+1, len(row))
		}
		if row[0] != Int(int64(it.Seq)) {
			t.Errorf("第 %d 行序号 = %q，期望 %q", i+1, row[0], Int(int64(it.Seq)))
		}
		if row[1] != it.AssetName {
			t.Errorf("第 %d 行资产 = %q，期望 %q", i+1, row[1], it.AssetName)
		}
		// 第 7..10 列是 A / T / V / R
		for col, want := range []string{Num(it.A), Num(it.T), Num(it.V), Num(it.R)} {
			if got := row[6+col]; got != want {
				t.Errorf("第 %d 行第 %d 列 = %q，期望 %q", i+1, 7+col, got, want)
			}
		}
		if row[10] != LevelLabel(it.RiskLevel) {
			t.Errorf("第 %d 行等级 = %q，期望 %q", i+1, row[10], LevelLabel(it.RiskLevel))
		}
	}

	// 先立阳性对照（K3「等级」是文本列，必须被认成文本），
	// 再断言数值列不是文本。顺序不能反——对照失效时，
	// 后面「不是文本」的结论也就没有意义了。
	assertCellIsText(t, f, sheetItems, "K3")
	assertCellIsNumeric(t, f, sheetItems, "J3") // J 列 = R 值
	assertCellIsNumeric(t, f, sheetItems, "G3") // G 列 = A 值
}

// TestExcelMatrixSheet 矩阵的两个块：计数块与等级块。
func TestExcelMatrixSheet(t *testing.T) {
	data := testData()
	raw, err := buildExcel(data)
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}
	f, err := excelize.OpenReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("读回 xlsx 失败: %v", err)
	}
	defer func() { _ = f.Close() }()

	rows, err := f.GetRows(sheetMatrix)
	if err != nil {
		t.Fatalf("读取矩阵表失败: %v", err)
	}

	// 计数块：标题(1) + 表头(2) + 5 行 = 第 3..7 行
	for sev := 1; sev <= 5; sev++ {
		row := rows[sev+1]
		for imp := 1; imp <= 5; imp++ {
			cell := data.Matrix.Cell(uint8(imp), uint8(sev))
			if got := row[imp]; got != Int(cell.Count) {
				t.Errorf("矩阵计数 (重要性=%d, 严重程度=%d) = %q，期望 %q",
					imp, sev, got, Int(cell.Count))
			}
		}
	}

	// 等级块在空一行之后：表头在 Excel 第 grid+4 = 9 行（1 基），
	// 即切片下标 grid+3。
	levelHeaderIdx := data.Matrix.GridSize + 3
	if len(rows) <= levelHeaderIdx {
		t.Fatalf("矩阵表只有 %d 行，等级块缺失（期望有第二块）", len(rows))
	}
	for sev := 1; sev <= 5; sev++ {
		row := rows[levelHeaderIdx+sev]
		for imp := 1; imp <= 5; imp++ {
			cell := data.Matrix.Cell(uint8(imp), uint8(sev))
			if got := row[imp]; got != LevelLabel(cell.Level) {
				t.Errorf("矩阵等级 (重要性=%d, 严重程度=%d) = %q，期望 %q",
					imp, sev, got, LevelLabel(cell.Level))
			}
		}
	}

	// 两个块的类型也要分开：计数块是数值（业务方要按重要性/严重程度做透视），
	// 等级块是文本。B3 是计数块第一格，B10 是等级块第一格（表头在第 9 行）。
	assertCellIsText(t, f, sheetMatrix, "B10")
	assertCellIsNumeric(t, f, sheetMatrix, "B3")
}

// TestExcelEmptyItems 空数据也要是一份能打开的合法文件。
func TestExcelEmptyItems(t *testing.T) {
	data := testData()
	data.Items = nil
	data.Assets = nil

	raw, err := buildExcel(data)
	if err != nil {
		t.Fatalf("空数据生成 xlsx 失败: %v", err)
	}
	f, err := excelize.OpenReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("空数据的 xlsx 无法读回: %v", err)
	}
	defer func() { _ = f.Close() }()
}

// ------------------------------------------------------------ 单元格类型断言

// excelTextTypes 会把值当字符串处理的单元格类型集合。
//
// 「是文本」有多个入口：SetCellValue(string) 走 SetCellStr → t="s"（共享字符串）；
// 带公式的字符串走 t="str"；富文本走 t="inlineStr"。实现里若换成
// SetCellStr/SetCellDefault 任一写法，命中的都是这三个之一。
var excelTextTypes = []excelize.CellType{
	excelize.CellTypeSharedString,
	excelize.CellTypeInlineString,
	excelize.CellTypeFormula,
}

// assertCellIsNumeric 断言单元格是数值而不是文本。
//
// ▍为什么不能写 cellType == excelize.CellTypeNumber
//
// excelize 的 GetCellType 直接返回 OOXML 里的 t 属性。而数值单元格在 OOXML
// 里**根本不写 t** —— 数值是单元格的默认类型，excelize 写数值时显式置
// c.T = ""。于是 GetCellType 落到映射表的零值上，返回 CellTypeUnset(=0)，
// 而不是 CellTypeNumber。所以那个写法**恒不成立**，一写就是永久红灯。
// 反过来若改成断言 CellTypeUnset，又会在一堆别的场景下（空格、纯样式单元格）
// 同时为真，等于没断言。
//
// 真正有区分度的是「字符串类型」：文本一定会被打上 t="s"/"str"/"inlineStr"。
// 所以这里断言目标列**不属于**文本类型集合。
func assertCellIsNumeric(t *testing.T, f *excelize.File, sheet, cell string) {
	t.Helper()
	cellType, err := f.GetCellType(sheet, cell)
	if err != nil {
		t.Fatalf("读取 %s!%s 的单元格类型失败: %v", sheet, cell, err)
	}
	for _, textType := range excelTextTypes {
		if cellType == textType {
			t.Errorf("%s!%s 的类型是 %v（字符串），期望数值 —— "+
				"数值写成了文本，用户无法求和/排序", sheet, cell, cellType)
			return
		}
	}
}

// assertCellIsText 是上面那位的阳性对照：证明「文本类型会被认出来」这件事
// 在当前 excelize 版本下确实成立。
//
// 每个数值断言前都先跑一次对照。哪天 excelize 改了内部表示（比如给数值也补上
// t="n"），对照会先把测试打红，而不是让 assertCellIsNumeric 静默地永远通过。
func assertCellIsText(t *testing.T, f *excelize.File, sheet, cell string) {
	t.Helper()
	cellType, err := f.GetCellType(sheet, cell)
	if err != nil {
		t.Fatalf("读取 %s!%s 的单元格类型失败: %v", sheet, cell, err)
	}
	if cellType != excelize.CellTypeSharedString {
		t.Fatalf("阳性对照失败：%s!%s 是文本，按当前 excelize 应被认成共享字符串，"+
			"实际拿到 %v。这说明类型断言已经失效，后面的数值断言不能作为依据",
			sheet, cell, cellType)
	}
}
