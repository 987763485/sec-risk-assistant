package spreadsheet

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ------------------------------------------------------------------ 格式嗅探

// TestDetectFormatUsesMagicNotExtension 确认判据是魔数而不是扩展名。
//
// 这条是必须钉住的：真实场景里用户会把 xlsx 改名成 .csv 上传
// （或者反过来），而浏览器上报的 MIME 更是五花八门。若按扩展名判断，
// 一个改名文件会走进 CSV 分支，报出「缺少必需列」——把用户引向
// 完全错误的方向。
func TestDetectFormatUsesMagicNotExtension(t *testing.T) {
	xlsx, err := WriteXLSX([]SheetSpec{{
		Name:   "资产台账",
		Header: []string{"资产名称", "IP 地址"},
		Rows:   [][]string{{"核心交换机", "10.0.0.1"}},
	}})
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}
	if got := DetectFormat(xlsx); got != FormatXLSX {
		t.Errorf("xlsx 字节流的格式判定为 %q，期望 %q", got, FormatXLSX)
	}

	// 关键断言：即便它被命名为 .csv，内容也还是 xlsx。
	// 判据只看字节流，因此这里不需要（也不该）有任何文件名参与。
	if got := DetectFormat([]byte("资产名称,IP 地址\n核心交换机,10.0.0.1\n")); got != FormatCSV {
		t.Errorf("纯文本判定为 %q，期望 %q", got, FormatCSV)
	}
	if got := DetectFormat([]byte{0x50, 0x4B, 0x03, 0x04, 0x00}); got != FormatXLSX {
		t.Errorf("PK 开头的字节流判定为 %q，期望 %q", got, FormatXLSX)
	}
}

// TestIsZipRejectsFakeHeader 确认 IsZip 不会被伪造的 PK 头骗过。
func TestIsZipRejectsFakeHeader(t *testing.T) {
	fake := append([]byte{'P', 'K', 0x03, 0x04}, bytes.Repeat([]byte{0x00}, 64)...)
	if IsZip(fake) {
		t.Error("一个只有 PK 头、内容不是 zip 的字节流被判成了合法 zip")
	}
	real, err := WriteXLSX([]SheetSpec{{Name: "S", Header: []string{"A"}, Rows: [][]string{{"1"}}}})
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}
	if !IsZip(real) {
		t.Error("真实的 xlsx 没有被判成 zip")
	}
}

// ------------------------------------------------------------------ xlsx 往返

func TestReadXLSXRoundTrip(t *testing.T) {
	data, err := WriteXLSX([]SheetSpec{{
		Name:   "资产台账",
		Header: []string{"资产名称", "IP 地址", "端口"},
		Rows: [][]string{
			{"核心交换机", "10.0.0.1", "22"},
			{"数据库主库", "10.0.0.9", "3306"},
		},
	}})
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}

	sheet, err := Read(data, MaxRows)
	if err != nil {
		t.Fatalf("读取 xlsx 失败: %v", err)
	}
	if sheet.Format != FormatXLSX {
		t.Errorf("格式为 %q，期望 %q", sheet.Format, FormatXLSX)
	}
	if len(sheet.Rows) != 3 {
		t.Fatalf("读到 %d 行，期望 3 行（1 行表头 + 2 行数据）", len(sheet.Rows))
	}
	if got := sheet.Rows[0].Cells; got[0] != "资产名称" || got[2] != "端口" {
		t.Errorf("表头内容不对: %v", got)
	}
	if got := sheet.Rows[1].Cells; got[0] != "核心交换机" || got[1] != "10.0.0.1" || got[2] != "22" {
		t.Errorf("第一行数据不对: %v", got)
	}
}

// TestReadXLSXKeepsRowNumbersWithBlankLines 确认中间的空行不会让行号错位。
//
// 这是本包存在的核心理由之一。excelize 的 GetRows 按行序返回（含中间空行），
// 因此下标 +1 必须等于 Excel 里看到的行号。
func TestReadXLSXKeepsRowNumbersWithBlankLines(t *testing.T) {
	data, err := WriteXLSX([]SheetSpec{{
		Name:   "资产台账",
		Header: []string{"资产名称", "IP 地址"},
		Rows: [][]string{
			{"第一台", "10.0.0.1"},
			{"", ""}, // 空行
			{"", ""}, // 空行
			{"第四台", "10.0.0.4"},
		},
	}})
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}

	sheet, err := Read(data, MaxRows)
	if err != nil {
		t.Fatalf("读取 xlsx 失败: %v", err)
	}
	if len(sheet.Rows) != 3 {
		t.Fatalf("读到 %d 行，期望 3 行（表头 + 2 行数据，空行被跳过）", len(sheet.Rows))
	}
	if sheet.Rows[1].Number != 2 {
		t.Errorf("第二行数据源行号为 %d，期望 2", sheet.Rows[1].Number)
	}
	// 「第四台」在 Excel 里位于第 5 行（表头 1 + 数据 2,3,4 = 5）。
	// 如果行号取自「第几条记录」，这里会得到 3。
	if sheet.Rows[2].Number != 5 {
		t.Errorf("「第四台」的源行号为 %d，期望 5（Excel 里它就在第 5 行）", sheet.Rows[2].Number)
	}
	if sheet.Rows[2].Cells[0] != "第四台" {
		t.Errorf("第三行内容为 %v，期望首格是「第四台」", sheet.Rows[2].Cells)
	}
}

// TestWriteXLSXHasNoLeftoverDefaultSheet 确认产物里没有多余的空白表。
func TestWriteXLSXHasNoLeftoverDefaultSheet(t *testing.T) {
	data, err := WriteXLSX([]SheetSpec{
		{Name: "资产台账", Header: []string{"A"}, Rows: [][]string{{"1"}}},
		{Name: "填写说明", Header: []string{"列名", "说明"}, Rows: [][]string{{"A", "示例"}}},
	})
	if err != nil {
		t.Fatalf("生成 xlsx 失败: %v", err)
	}

	sheet, err := Read(data, MaxRows)
	if err != nil {
		t.Fatalf("读取 xlsx 失败: %v", err)
	}
	// Read 只读第一张表；这里借它的存在间接确认第一张是「资产台账」
	// 而不是残留的 Sheet1。
	if sheet.Rows[0].Cells[0] != "A" {
		t.Errorf("第一张表内容为 %v，期望表头是 A", sheet.Rows[0].Cells)
	}
}

// ------------------------------------------------------------------ CSV 编码

func TestReadCSVUTF8WithBOM(t *testing.T) {
	raw := "\ufeff资产名称,IP 地址\n核心交换机,10.0.0.1\n"
	sheet, err := Read([]byte(raw), MaxRows)
	if err != nil {
		t.Fatalf("读取 CSV 失败: %v", err)
	}
	// BOM 若没被剥掉，第一个列名会变成 "\ufeff资产名称"，
	// 与模板定义对不上，报出的是「缺少必需列」这种误导性错误。
	if got := sheet.Rows[0].Cells[0]; got != "资产名称" {
		t.Errorf("首列名为 %q，期望 %q（BOM 未被剥掉）", got, "资产名称")
	}
}

func TestReadCSVGBK(t *testing.T) {
	utf8Text := "资产名称,IP 地址\n核心交换机,10.0.0.1\n"
	gbkBytes, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(utf8Text))
	if err != nil {
		t.Fatalf("构造 GBK 数据失败: %v", err)
	}

	sheet, err := Read(gbkBytes, MaxRows)
	if err != nil {
		t.Fatalf("读取 GBK CSV 失败: %v", err)
	}
	if got := sheet.Rows[0].Cells[0]; got != "资产名称" {
		t.Errorf("GBK 文件解出的首列名为 %q，期望 %q", got, "资产名称")
	}
	if got := sheet.Rows[1].Cells[0]; got != "核心交换机" {
		t.Errorf("GBK 文件解出的数据为 %q，期望 %q", got, "核心交换机")
	}
}

// TestReadCSVKeepsLineNumbersWithBlankLines 确认 CSV 的空白行不影响行号。
//
// csv.Reader **会跳过空行**，因此行号绝不能取自「第几条记录」。
// 这里用 FieldPos 拿源文件行号，这条测试就是钉住这个行为。
func TestReadCSVKeepsLineNumbersWithBlankLines(t *testing.T) {
	raw := strings.Join([]string{
		"资产名称,IP 地址",   // 第 1 行
		"第一台,10.0.0.1", // 第 2 行
		"",             // 第 3 行（空）
		"",             // 第 4 行（空）
		"第五台,10.0.0.5", // 第 5 行
		"",
	}, "\n")

	sheet, err := Read([]byte(raw), MaxRows)
	if err != nil {
		t.Fatalf("读取 CSV 失败: %v", err)
	}
	if len(sheet.Rows) != 3 {
		t.Fatalf("读到 %d 行，期望 3 行", len(sheet.Rows))
	}
	if sheet.Rows[1].Number != 2 {
		t.Errorf("第二行的源行号为 %d，期望 2", sheet.Rows[1].Number)
	}
	if sheet.Rows[2].Number != 5 {
		t.Errorf("第三行的源行号为 %d，期望 5（用记录序号会得到 3）", sheet.Rows[2].Number)
	}
}

func TestReadCSVToleratesBareQuotes(t *testing.T) {
	// 资产名里有一个裸双引号。默认设置下 csv.Reader 会整份报错，
	// 而用户真正需要的是「哪一行有问题」。
	raw := "资产名称,备注\n核心\"交换机,机房里\n"
	sheet, err := Read([]byte(raw), MaxRows)
	if err != nil {
		t.Fatalf("含裸引号的 CSV 应当可解析，却失败了: %v", err)
	}
	if len(sheet.Rows) != 2 {
		t.Fatalf("读到 %d 行，期望 2 行", len(sheet.Rows))
	}
	if !strings.Contains(sheet.Rows[1].Cells[0], "核心") {
		t.Errorf("数据行内容异常: %v", sheet.Rows[1].Cells)
	}
}

// ------------------------------------------------------------------ 边界

func TestReadRejectsEmptyAndOversized(t *testing.T) {
	if _, err := Read(nil, MaxRows); !errors.Is(err, ErrEmpty) {
		t.Errorf("空内容的错误为 %v，期望 ErrEmpty", err)
	}
	// 只有空行、没有任何内容
	if _, err := Read([]byte("\n\n\n,,\n"), MaxRows); !errors.Is(err, ErrEmpty) {
		t.Errorf("纯空行文件的错误为 %v，期望 ErrEmpty", err)
	}
	// 超体积
	big := bytes.Repeat([]byte("a"), MaxFileSize+1)
	if _, err := Read(big, MaxRows); err == nil {
		t.Error("超过体积上限的文件应当被拒绝，却没有")
	}
}

func TestReadRejectsTooManyRows(t *testing.T) {
	var b strings.Builder
	b.WriteString("A,B\n")
	for i := 0; i < 10; i++ {
		b.WriteString("x,y\n")
	}
	if _, err := Read([]byte(b.String()), 3); !errors.Is(err, ErrTooManyRows) {
		t.Errorf("超过行数上限的错误为 %v，期望 ErrTooManyRows", err)
	}
}

func TestReadTrimsTrailingEmptyColumnsAndClampsCells(t *testing.T) {
	// 模拟「整行全选」：尾部带一堆空列。
	raw := "A,B,C,,\n第一列,第二列,,\n"
	sheet, err := Read([]byte(raw), MaxRows)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	// 表头有三个非空格，尾部的两个空列被裁掉后应恰好剩 3 列；
	// 若裁剪逻辑失效，这里会变成 5。
	if got := len(sheet.Rows[0].Cells); got != 3 {
		t.Errorf("表头长度为 %d，期望 3（尾部空列应被裁掉）", got)
	}
	// 数据行只有两个非空格
	if got := len(sheet.Rows[1].Cells); got != 2 {
		t.Errorf("数据行长度为 %d，期望 2（尾部空列应被裁掉）", got)
	}
	if got := sheet.Rows[1].Cells[1]; got != "第二列" {
		t.Errorf("第二格为 %q，期望 %q", got, "第二列")
	}

	// 单元格规整：首尾空白裁掉、\r\n 归一、不断行空格换成普通空格
	nb := "第一列\u00a0A,\r\n  第二列  ,"
	sheet2, err := Read([]byte(nb), MaxRows)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	// 注意：\r\n 出现在字段内会使 csv.Reader 认为记录尚未结束，
	// 因此这里只断言不断行空格与首尾空白被处理。
	if got := sheet2.Rows[0].Cells[0]; got != "第一列 A" {
		t.Errorf("不断行空格未被归一: %q", got)
	}

	long := strings.Repeat("字", MaxCellRunes+50)
	sheet3, err := Read([]byte("A\n"+long+"\n"), MaxRows)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got := len([]rune(sheet3.Rows[1].Cells[0])); got != MaxCellRunes {
		t.Errorf("超长单元格被裁到 %d 个字符，期望 %d", got, MaxCellRunes)
	}
}

// TestReadCSVUsesCorrectLineNumberOnLongFile 用一份较长且夹空行的文件
// 确认行号在整份文件范围内都正确（防止偏移量只在开头对得上）。
func TestReadCSVUsesCorrectLineNumberOnLongFile(t *testing.T) {
	var lines []string
	lines = append(lines, "资产名称,IP 地址") // 第 1 行
	for i := 1; i <= 200; i++ {
		if i%10 == 0 {
			lines = append(lines, "") // 每 10 条插一个空行
		}
		lines = append(lines, "资产"+itoa(i)+",10.0.0."+itoa(i))
	}

	sheet, err := Read([]byte(strings.Join(lines, "\n")), MaxRows)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(sheet.Rows) != 201 {
		t.Fatalf("读到 %d 行，期望 201 行（1 表头 + 200 数据）", len(sheet.Rows))
	}
	// 空行出现在第 11、22、33… 行，因此第 200 条数据落在源文件第 221 行。
	if got, want := sheet.Rows[200].Number, 221; got != want {
		t.Errorf("第 200 条数据的源行号为 %d，期望 %d", got, want)
	}
	if got := sheet.Rows[200].Cells[0]; got != "资产200" {
		t.Errorf("第 200 条数据内容为 %q，期望 %q", got, "资产200")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
