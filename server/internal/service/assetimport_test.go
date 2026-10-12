package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/spreadsheet"
)

// ▍这个文件只测纯函数。
//
// 导入功能里真正容易出错的部分不是「有没有落库」，而是**「哪一格为什么不
// 合法、报的是第几行」**——那是 P2 的验收标志，也是用户唯一能感知的东西。
// 这部分逻辑恰好不依赖数据库（parseImportRow 的依赖全是入参），因此可以
// 用最便宜的方式覆盖到。

// testAssetTypes 一份覆盖「码 / 中文名 / 停用 / 重名 / 名码相同」的字典。
func testAssetTypes() map[string]model.Dictionary {
	items := []model.Dictionary{
		{Code: "server", Name: "服务器", Enabled: true},
		{Code: "database", Name: "数据库", Enabled: true},
		{Code: "network", Name: "网络设备", Enabled: true},
		{Code: "legacy", Name: "遗留系统", Enabled: false},
		// 重名：别名表必须把「重复名」标成歧义后剔除，否则按名称解析的
		// 结果会随 Go 的 map 遍历顺序在请求之间跳变。
		{Code: "aaa_dup", Name: "重复名", Enabled: true},
		{Code: "zzz_dup", Name: "重复名", Enabled: true},
		// 名称与另一个码相同：不建别名，否则「写码」与「写名」被混为一谈。
		{Code: "switch", Name: "switch", Enabled: true},
	}
	out := make(map[string]model.Dictionary, len(items))
	for _, it := range items {
		out[it.Code] = it
	}
	return out
}

// ------------------------------------------------------------------ 列定义

// TestImportColumnGuidesCoverEveryColumn 守着「模板加了一列却忘了写说明」。
//
// 这类遗漏只会以「用户看到一列没有解释的表头」的形式暴露，而那是最后
// 才可能被反馈回来的问题。
func TestImportColumnGuidesCoverEveryColumn(t *testing.T) {
	keys := make(map[string]struct{}, len(importColumns))
	headers := make(map[string]struct{}, len(importColumns))

	for _, col := range importColumns {
		if _, dup := keys[col.Key]; dup {
			t.Fatalf("列定义里出现重复的 Key %q", col.Key)
		}
		keys[col.Key] = struct{}{}

		// 表头必须两两不同：mapImportColumns 按表头文字匹配，
		// 两列同名会让后一列永远匹配不上，而用户完全看不出来。
		if _, dup := headers[col.Header]; dup {
			t.Errorf("列定义里出现重复的表头 %q", col.Header)
		}
		headers[col.Header] = struct{}{}

		guide, ok := importColumnGuides[col.Key]
		if !ok {
			t.Errorf("列 %q（%s）缺少填写说明", col.Key, col.Header)
			continue
		}
		if strings.TrimSpace(guide.Note) == "" {
			t.Errorf("列 %q 的填写说明为空", col.Key)
		}
		if strings.TrimSpace(guide.Sample) == "" {
			t.Errorf("列 %q 缺少示例值", col.Key)
		}
	}

	for key := range importColumnGuides {
		if _, ok := keys[key]; !ok {
			t.Errorf("填写说明里的 %q 在列定义中不存在，说明已过期", key)
		}
	}
}

// TestImportTemplateTextColumnLettersAreInSyncWithColumnOrder 守住列序与
// 「强制文本列」的对应关系。
//
// 资产编号与 IP 地址被设为文本格式，靠的是 B / D 这两个列字母。用户调整
// 列序（或我们改 importColumns）而忘了同步这两个字母时，产物的样子完全
// 正常，只会在用户那边表现为「编号前面的 0 不见了」。
func TestImportTemplateTextColumnLettersAreInSyncWithColumnOrder(t *testing.T) {
	want := map[string]string{"asset_no": "B", "ip_address": "D"}

	// ① 声明的字母本身就是那两个（防「写成了别的列」）
	declared := make(map[string]struct{}, len(importTemplateTextColumns))
	for _, letter := range importTemplateTextColumns {
		declared[letter] = struct{}{}
	}
	for key, letter := range want {
		if _, ok := declared[letter]; !ok {
			t.Errorf("强制文本列里缺少 %s（%s 所在的列），实际声明: %v",
				letter, key, importTemplateTextColumns)
		}
	}
	if len(importTemplateTextColumns) != len(want) {
		t.Errorf("强制文本列有 %d 个，期望 %d 个", len(importTemplateTextColumns), len(want))
	}

	// ② 列序确实让这两个字母落在该落的两列上（防「列序改了没同步字母」）。
	// 只做 ① 或只做 ② 都不够：两个方向各自对应一类漏法。
	for key, letter := range want {
		idx := columnIndexByKey(t, key)
		got, err := excelize.ColumnNumberToName(idx + 1)
		if err != nil {
			t.Fatalf("列字母换算失败: %v", err)
		}
		if got != letter {
			t.Errorf("列 %q 位于第 %s 列，但模板把它设成了文本格式的 %s 列",
				key, got, letter)
		}
	}
}

func columnIndexByKey(t *testing.T, key string) int {
	t.Helper()
	for i, col := range importColumns {
		if col.Key == key {
			return i
		}
	}
	t.Fatalf("列定义里没有 %q", key)
	return -1
}

// ------------------------------------------------------------------ 表头映射

func TestMapImportColumnsMatchesByHeaderName(t *testing.T) {
	// 列顺序与模板不同，且混进了模板之外的列
	header := spreadsheet.Row{Number: 1, Cells: []string{
		"备注", "资产名称", "随手加的一列", "资产类型", "IP 地址",
	}}

	index, missing := mapImportColumns(header)
	if len(missing) > 0 {
		t.Fatalf("不应报缺列，实际缺: %v", missing)
	}

	for key, want := range map[string]int{
		"description": 0,
		"name":        1,
		"asset_type":  3,
		"ip_address":  4,
		// 模板之外的列被忽略，不占下标
		"port": -1,
	} {
		if got := index[key]; got != want {
			t.Errorf("列 %q 下标 = %d，期望 %d", key, got, want)
		}
	}
}

func TestMapImportColumnsReportsMissingRequired(t *testing.T) {
	index, missing := mapImportColumns(spreadsheet.Row{Cells: []string{"资产名称"}})

	if len(missing) != 1 || missing[0] != "资产类型" {
		t.Fatalf("缺列报告不准确，实际: %v", missing)
	}
	if index["name"] != 0 {
		t.Errorf("资产名称下标 = %d，期望 0", index["name"])
	}
}

func TestMapImportColumnsTakesFirstDuplicateHeader(t *testing.T) {
	index, _ := mapImportColumns(spreadsheet.Row{Cells: []string{
		"资产名称", "资产名称", "资产类型",
	}})
	if index["name"] != 0 {
		t.Errorf("重复表头应取第一次出现的位置（与 Excel 的 VLOOKUP 一致），实际 %d",
			index["name"])
	}
}

// ------------------------------------------------------------------ 类型解析

func TestBuildAssetTypeAliasIndex(t *testing.T) {
	alias := buildAssetTypeAliasIndex(testAssetTypes())

	for name, want := range map[string]string{
		"服务器":  "server",
		"数据库":  "database",
		"网络设备": "network",
		"遗留系统": "legacy",
	} {
		if got, ok := alias[name]; !ok || got != want {
			t.Errorf("别名 %q = %q（存在=%v），期望 %q", name, got, ok, want)
		}
	}

	if got, ok := alias["重复名"]; ok {
		t.Errorf("重名类型不应进入别名表，否则解析结果会跳变；实际指向 %q", got)
	}
	if got, ok := alias["switch"]; ok {
		t.Errorf("名称与码相同时不应建别名；实际指向 %q", got)
	}
}

// TestBuildAssetTypeAliasIndexIsStable 确认结果与 map 遍历顺序无关。
func TestBuildAssetTypeAliasIndexIsStable(t *testing.T) {
	types := testAssetTypes()
	first := buildAssetTypeAliasIndex(types)

	for i := 0; i < 50; i++ {
		next := buildAssetTypeAliasIndex(types)
		if len(next) != len(first) {
			t.Fatalf("第 %d 次构建的别名表大小不同: %d vs %d", i, len(next), len(first))
		}
		for k, v := range first {
			if next[k] != v {
				t.Fatalf("第 %d 次构建的别名 %q = %q，期望 %q", i, k, next[k], v)
			}
		}
	}
}

func TestResolveAssetTypeValue(t *testing.T) {
	types := testAssetTypes()
	alias := buildAssetTypeAliasIndex(types)

	cases := []struct {
		in       string
		wantCode string
		wantOK   bool
	}{
		{"server", "server", true},
		{"服务器", "server", true},
		// 停用项仍能解析：能不能用是调用方（parseImportRow）的规则
		{"legacy", "legacy", true},
		{"遗留系统", "legacy", true},
		{"core-switch", "", false},
		{"", "", false},
		{"重复名", "", false},
	}
	for _, c := range cases {
		got, ok := resolveAssetTypeValue(types, alias, c.in)
		if got != c.wantCode || ok != c.wantOK {
			t.Errorf("resolveAssetTypeValue(%q) = (%q, %v)，期望 (%q, %v)",
				c.in, got, ok, c.wantCode, c.wantOK)
		}
	}
}

// ------------------------------------------------------------------ 逐格校验

// importTestIndex 按模板列序构造「列键 → 下标」映射。
func importTestIndex(t *testing.T) map[string]int {
	t.Helper()
	header := make([]string, 0, len(importColumns))
	for _, col := range importColumns {
		header = append(header, col.Header)
	}
	index, missing := mapImportColumns(spreadsheet.Row{Number: 1, Cells: header})
	if len(missing) > 0 {
		t.Fatalf("模板自身的列定义就不完整，缺少: %v", missing)
	}
	return index
}

// buildRow 按「列键 → 值」铺出一行，未给出的列留空。
func buildRow(t *testing.T, number int, index map[string]int, values map[string]string) spreadsheet.Row {
	t.Helper()
	width := 0
	for _, idx := range index {
		if idx+1 > width {
			width = idx + 1
		}
	}
	cells := make([]string, width)
	for key, v := range values {
		idx, ok := index[key]
		if !ok {
			t.Fatalf("列键 %q 不在模板中", key)
		}
		cells[idx] = v
	}
	return spreadsheet.Row{Number: number, Cells: cells}
}

func parseRow(t *testing.T, values map[string]string) (parsedImportRow, []ImportRowError) {
	t.Helper()
	types := testAssetTypes()
	index := importTestIndex(t)
	// 行号刻意用一个不像「第 1 个数据行」的数字，避免把「源文件行号」
	// 与「数据行序号」混淆时测试仍然通过。
	return parseImportRow(buildRow(t, 137, index, values), index, types,
		buildAssetTypeAliasIndex(types))
}

func TestParseImportRowAcceptsMinimalRowAndFillsDefaults(t *testing.T) {
	parsed, errs := parseRow(t, map[string]string{
		"name":       "核心交换机-01",
		"asset_type": "服务器",
	})
	if len(errs) > 0 {
		t.Fatalf("合法行不应报错，实际: %v", errs)
	}

	if parsed.Asset.Name != "核心交换机-01" {
		t.Errorf("名称 = %q", parsed.Asset.Name)
	}
	if parsed.Asset.AssetType != "server" {
		t.Errorf("资产类型 = %q，期望 server（中文名应被解析成码）", parsed.Asset.AssetType)
	}
	if parsed.Asset.Importance != model.ImportanceDefault {
		t.Errorf("重要性默认 = %d，期望 %d",
			parsed.Asset.Importance, model.ImportanceDefault)
	}
	if parsed.Asset.Status != model.AssetStatusInUse {
		t.Errorf("状态默认 = %q，期望 %q", parsed.Asset.Status, model.AssetStatusInUse)
	}
	if parsed.Asset.AssetNo != nil {
		t.Errorf("留空资产编号时应为 nil（可空唯一索引下多条 NULL 不冲突），实际 %q",
			*parsed.Asset.AssetNo)
	}
	if parsed.Asset.Port != nil {
		t.Errorf("留空端口时应为 nil，实际 %d", *parsed.Asset.Port)
	}
	if parsed.GroupPath != "" {
		t.Errorf("留空资产组时应为空路径，实际 %q", parsed.GroupPath)
	}
}

// TestParseImportRowKeepsSourceLineNumber 是本文件的重点：
// 报出的行号必须是**源文件行号**，用户才能直接跳到那一行。
func TestParseImportRowKeepsSourceLineNumber(t *testing.T) {
	_, errs := parseRow(t, map[string]string{
		"name": "x", "asset_type": "server", "port": "70000",
	})

	if len(errs) != 1 {
		t.Fatalf("期望 1 条错误，实际 %d 条: %v", len(errs), errs)
	}
	if errs[0].Row != 137 {
		t.Errorf("错误行号 = %d，期望 137（须是源文件行号，不是数据行序号）", errs[0].Row)
	}
	if errs[0].Column != "端口" {
		t.Errorf("错误列名 = %q，期望 端口", errs[0].Column)
	}
	if errs[0].Value != "70000" {
		t.Errorf("错误原值 = %q，期望 70000", errs[0].Value)
	}
	if errs[0].Message == "" {
		t.Error("错误说明不能为空——只说「不合法」用户不知道该怎么改")
	}
}

// TestParseImportRowAccumulatesEveryBadCell 确认一次报全，而不是首错即返。
//
// 首错即返会让用户改一处、传一次，一份 20 处错误的文件要传 20 遍。
func TestParseImportRowAccumulatesEveryBadCell(t *testing.T) {
	_, errs := parseRow(t, map[string]string{
		"name":       "",
		"asset_type": "不存在的类型",
		"ip_address": "999.1.1.1",
		"port":       "abc",
		"importance": "9",
		"status":     "在用中",
		"group":      "总部//机房",
	})

	wantColumns := []string{"资产名称", "资产类型", "IP 地址", "端口", "重要性", "状态", "资产组"}
	got := make([]string, 0, len(errs))
	for _, e := range errs {
		got = append(got, e.Column)
	}
	if strings.Join(got, ",") != strings.Join(wantColumns, ",") {
		t.Fatalf("错误列顺序/数量不符\n实际: %v\n期望: %v", got, wantColumns)
	}
	for _, e := range errs {
		if e.Row != 137 {
			t.Errorf("列 %q 的错误行号 = %d，期望 137", e.Column, e.Row)
		}
	}
}

// TestParseImportRowRejectsDisabledAssetType 停用类型不允许用于新导入。
func TestParseImportRowRejectsDisabledAssetType(t *testing.T) {
	_, errs := parseRow(t, map[string]string{
		"name": "x", "asset_type": "遗留系统",
	})
	if len(errs) != 1 {
		t.Fatalf("期望 1 条错误，实际 %v", errs)
	}
	if errs[0].Column != "资产类型" || !strings.Contains(errs[0].Message, "停用") {
		t.Errorf("错误应指明「已停用」，实际: %+v", errs[0])
	}
}

func TestParseImportRowAcceptsAliasesAndNormalizesCells(t *testing.T) {
	parsed, errs := parseRow(t, map[string]string{
		"name":        "  带空格的名称  ",
		"asset_type":  "server",
		"asset_no":    "2026/Q1/NET-001",
		"port":        " 443 ",
		"importance":  "5",
		"status":      "已下线",
		"tags":        "核心,生产；测试、备份",
		"group":       "/总部/华东区/",
		"ip_address":  "192.168.1.10",
		"description": "承载内网核心交换",
	})
	if len(errs) > 0 {
		t.Fatalf("合法行不应报错，实际: %v", errs)
	}

	if parsed.Asset.Name != "带空格的名称" {
		t.Errorf("名称两端空白应被裁掉，实际 %q", parsed.Asset.Name)
	}
	if parsed.Asset.AssetNoValue() != "2026/Q1/NET-001" {
		t.Errorf("资产编号 = %q（带斜杠的编号在企业台账里很常见，应被接受）",
			parsed.Asset.AssetNoValue())
	}
	if parsed.Asset.PortValue() != 443 {
		t.Errorf("端口 = %d，期望 443", parsed.Asset.PortValue())
	}
	if parsed.Asset.Importance != 5 {
		t.Errorf("重要性 = %d，期望 5", parsed.Asset.Importance)
	}
	if parsed.Asset.Status != model.AssetStatusOffline {
		t.Errorf("状态 = %q，期望 offline（中文别名应被识别）", parsed.Asset.Status)
	}
	// 中文逗号、分号与顿号都当分隔符
	if parsed.Asset.Tags != "核心,生产,测试,备份" {
		t.Errorf("标签 = %q，期望 核心,生产,测试,备份", parsed.Asset.Tags)
	}
	// 首尾斜杠被裁掉：用户从别处复制路径时常常带上
	if parsed.GroupPath != "总部/华东区" {
		t.Errorf("资产组路径 = %q，期望 总部/华东区", parsed.GroupPath)
	}
}

// TestParseImportRowTagsAreOptional 确认未填标签时留下空串而不是报错。
//
// 空串与 NULL 在这里是等价的（assets.tags 非空默认 ”），
// 因此不需要为它引入可空语义。
func TestParseImportRowTagsAreOptional(t *testing.T) {
	parsed, errs := parseRow(t, map[string]string{"name": "x", "asset_type": "server"})
	if len(errs) > 0 {
		t.Fatalf("不应报错: %v", errs)
	}
	if parsed.Asset.Tags != "" {
		t.Errorf("未填标签时应为空串，实际 %q", parsed.Asset.Tags)
	}
}

// TestParseImportRowRejectsNumericLookingIP 是关键的一条：
// 只做「符合主机名字符集就放行」的校验会把 999.1.1.1 当成合法主机名收下。
func TestParseImportRowRejectsNumericLookingIP(t *testing.T) {
	for _, bad := range []string{"999.1.1.1", "192.168.1", "1.2.3.4.5"} {
		if _, errs := parseRow(t, map[string]string{
			"name": "x", "asset_type": "server", "ip_address": bad,
		}); len(errs) != 1 {
			t.Errorf("%q 应被拒绝，实际错误: %v", bad, errs)
		}
	}
	for _, ok := range []string{"192.168.1.10", "10.0.0.0/8", "fe80::1", "web-01.example.com"} {
		if _, errs := parseRow(t, map[string]string{
			"name": "x", "asset_type": "server", "ip_address": ok,
		}); len(errs) != 0 {
			t.Errorf("%q 应被接受，实际错误: %v", ok, errs)
		}
	}
}

// ------------------------------------------------------------------ 路径与标签

func TestNormalizeGroupPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"总部/华东区/机房A", "总部/华东区/机房A", true},
		{"/总部/华东区/", "总部/华东区", true},
		{" 总部 / 华东区 ", "总部/华东区", true},
		{"总部", "总部", true},
		{"", "", false},
		{"///", "", false},
		{"总部/", "总部", true},
		{"总部//机房", "", false},
		{"总部/ /机房", "", false},
		{strings.Repeat("a/", model.MaxAssetGroupDepth) + "a", "", false}, // 超层
		{strings.Repeat("层级", 40), "", false},                             // 单段超长
	}
	for _, c := range cases {
		got, ok := normalizeGroupPath(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("normalizeGroupPath(%q) = (%q, %v)，期望 (%q, %v)",
				c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSplitTagCell(t *testing.T) {
	got := splitTagCell("a,b，c;d；e、f")
	want := []string{"a", "b", "c", "d", "e", "f"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("splitTagCell = %v，期望 %v", got, want)
	}

	// 全空白单元格会被 splitTagCell 原样返回一个字段（它只是分隔符切分，
	// 不做校验），真正的「丢弃空标签」发生在 normalizeTags。这里端到端
	// 验证一遍，因为那才是用户会遇到的组合。
	tags, err := normalizeTags(splitTagCell("   "))
	if err != nil {
		t.Fatalf("全空白标签不应报错: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("全空白应归零为 0 个标签，实际 %v", tags)
	}
}

func TestParsePort(t *testing.T) {
	for _, ok := range []string{"1", "80", "65535"} {
		if _, err := parsePort(ok); err != nil {
			t.Errorf("parsePort(%q) 应成功，实际: %v", ok, err)
		}
	}
	// 0 不是合法端口，因此不能拿它当「未填写」的哨兵值。
	// 带空格的输入不在此列：spreadsheet 层读出时已裁剪，
	// parsePort 刻意不做第二次裁剪（见其函数注释）。
	for _, bad := range []string{"0", "65536", "-1", "abc", "", "80.5", " 443 "} {
		if _, err := parsePort(bad); err == nil {
			t.Errorf("parsePort(%q) 应失败", bad)
		}
	}
}

func TestResolveAssetStatusAlias(t *testing.T) {
	for raw, want := range map[string]model.AssetStatus{
		"in_use": model.AssetStatusInUse,
		"在用":     model.AssetStatusInUse,
		"使用中":    model.AssetStatusInUse,
		"闲置":     model.AssetStatusIdle,
		"已下线":    model.AssetStatusOffline,
		"已报废":    model.AssetStatusScrapped,
	} {
		got, ok := resolveAssetStatusAlias(raw)
		if !ok || got != want {
			t.Errorf("resolveAssetStatusAlias(%q) = (%q, %v)，期望 (%q, true)",
				raw, got, ok, want)
		}
	}
	// 只认明确的说法：近义词的边界说不清，收了一个就有第二个
	for _, bad := range []string{"在用中", "使用", "停用", "使用中设备"} {
		if got, ok := resolveAssetStatusAlias(bad); ok {
			t.Errorf("resolveAssetStatusAlias(%q) 不应被接受，实际 %q", bad, got)
		}
	}
}

// ------------------------------------------------------------------ 错误列表

func TestAppendImportErrorsTruncatesButKeepsCounting(t *testing.T) {
	preview := &AssetImportPreview{Errors: []ImportRowError{}}

	total := maxImportPreviewErrors + 37
	for i := 0; i < total; i++ {
		appendImportErrors(preview, []ImportRowError{{
			Row: i + 2, Column: "资产名称", Message: "第 " + fmt.Sprint(i+2) + " 行不合格",
		}})
	}

	if len(preview.Errors) != maxImportPreviewErrors {
		t.Errorf("错误条数 = %d，期望被截断到 %d", len(preview.Errors), maxImportPreviewErrors)
	}
	if !preview.TruncatedErrors {
		t.Error("截断后必须置 TruncatedErrors，否则前端会以为这就是全部错误")
	}
}

func TestSortedStringSetReturnsEmptySliceNotNil(t *testing.T) {
	// 返回 nil 会让 JSON 里出现 null，前端得为此多写一处空值判断
	got := sortedStringSet(map[string]struct{}{})
	if got == nil {
		t.Fatal("空集合应返回空切片而不是 nil")
	}
	if len(got) != 0 {
		t.Errorf("期望空切片，实际 %v", got)
	}

	got = sortedStringSet(map[string]struct{}{"b": {}, "a": {}, "c": {}})
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("应返回排好序的结果（便于 diff 与断言），实际 %v", got)
	}
}
