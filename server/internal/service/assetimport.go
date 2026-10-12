package service

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/spreadsheet"
	"secrisk/server/internal/repository"
)

// ▍导入的整体设计
//
// 两阶段：preview 只解析与校验、不落库；commit 重新上传同一份文件，
// 完整校验后**在单个事务里**写入。
//
// 为什么 commit 要重新校验而不是复用 preview 的结果：
// 服务端不持有任何导入会话状态。省一次上传的代价是引入一份有 TTL 的
// 内存缓存（多副本部署时会话粘滞）或一张临时表（要多一套清理），
// 而收益只是省掉几百 KB 的上行流量。校验规则只有一份，两阶段调用的是
// 同一个 parse —— 因此不存在「预览说没问题、提交却失败」的偏差。
//
// 为什么 commit 是原子的（任一行不合格则整批不写）：
// 半成功的导入会留下一个无法回答的问题——「台账里现在这批数据，
// 到底导完了还是没导完？」。用户拿着错误清单改完重传的成本，
// 远低于事后逐条比对哪些进去了哪些没进去。
//
// ▍组的「待创建」为什么可以不算行错误
//
// 「资产组不存在」有两种成因：用户写错了组名，或者这个组确实还没建。
// 前者必须拦下，后者不该拦——否则每导一次新清单都得先手工把组织架构
// 建一遍。区分两者的唯一办法是让用户明示意图，因此 preview 与 commit
// 都接受 create_missing_groups：
//
//	为 false → 这些行记错误，同时把它们引用的组汇总进 unmatched_groups，
//	           让用户能一次性看到「缺哪几个组」
//	为 true  → 这些行不记错误，缺失的组（含中间层级）在 commit 时建出来，
//	           汇总进 groups_to_create
//
// 前端切换这个开关时重新调一次 preview 即可（文件还在内存里），
// 这样界面上的各种计数永远与真实状态一致，不需要前端自己去分类错误。

// maxImportPreviewErrors 预览里最多回传多少条行错误。
//
// 上限存在的理由是响应体积：一份全错的 5000 行文件会产生上万条错误，
// 而界面上一次也就能看几十条。超出部分只计数不列出——用户看到
// 「错误 4820 条」就知道该整体重做，而不是逐条改。
const maxImportPreviewErrors = 200

// ImportMaxFileBytes 单个导入文件的体积上限。
//
// 导出给接口层，让它在读取请求体时就设上限。这一层不能省：服务层虽然
// 也会校验，但那时字节已经全在内存里了——一个 2 GB 的上传足以把进程打挂，
// 而这完全取决于客户端的行为。
const ImportMaxFileBytes int64 = spreadsheet.MaxFileSize

// importColumn 导入模板的一列。
type importColumn struct {
	// Header 中文列名，必须与模板逐字一致
	Header string
	// Key 内部标识，用于错误信息里指明是哪一列
	Key string
	// Required 是否必填
	Required bool
	// MaxRunes 长度上限（0 表示不单独限制）
	MaxRunes int
}

// importColumns 导入模板的列定义，顺序即模板列序。
//
// 模板生成（ImportTemplate）读的是同一份定义，因此不存在
// 「模板加了列但解析不认」这种只会在用户那边暴露的问题。
var importColumns = []importColumn{
	{Header: "资产名称", Key: "name", Required: true, MaxRunes: assetNameMaxRunes},
	{Header: "资产编号", Key: "asset_no", MaxRunes: assetNoMaxRunes},
	{Header: "资产类型", Key: "asset_type", Required: true, MaxRunes: 32},
	{Header: "IP 地址", Key: "ip_address", MaxRunes: assetIPMaxRunes},
	{Header: "端口", Key: "port"},
	{Header: "主机名", Key: "hostname", MaxRunes: assetHostnameMaxRunes},
	{Header: "操作系统", Key: "os_type", MaxRunes: assetOSTypeMaxRunes},
	{Header: "资产组", Key: "group", MaxRunes: 255},
	{Header: "重要性", Key: "importance"},
	{Header: "负责人", Key: "owner", MaxRunes: assetOwnerMaxRunes},
	{Header: "归属部门", Key: "department", MaxRunes: assetDepartmentMaxRunes},
	{Header: "状态", Key: "status", MaxRunes: 16},
	{Header: "标签", Key: "tags", MaxRunes: 255},
	{Header: "备注", Key: "description", MaxRunes: assetDescriptionMaxRunes},
}

// importColumnGuide 模板「填写说明」表里的逐列说明。
type importColumnGuide struct {
	// Note 这一列该填什么
	Note string
	// Sample 示例值。放在说明表里而不是数据表里，理由见 ImportTemplate。
	Sample string
	// Width 模板里的列宽（字符数）。0 表示使用默认宽度。
	Width float64
}

// importColumnGuides 逐列说明，键与 importColumns 的 Key 一一对应。
//
// 与 importColumns 分开维护是有意的：说明文字是给用户看的文案，会随
// 用户反馈反复调整；而列定义是校验依据，改动要慎重。混在一处会让人
// 因为「改个错别字」而误碰校验逻辑。覆盖关系由
// TestImportColumnGuidesCoverEveryColumn 强制，因此新增一列却忘了写
// 说明会在测试阶段就暴露，而不是等用户看到一列没有解释的表头。
var importColumnGuides = map[string]importColumnGuide{
	"name":        {Note: "资产的显示名称，最多 128 字", Sample: "核心交换机-01", Width: 24},
	"asset_no":    {Note: "可留空。1–64 位字母、数字或 _ . - /，须以字母或数字开头；全局唯一", Sample: "2026/Q1/NET-001", Width: 20},
	"asset_type":  {Note: "填类型码或中文名均可，取值见本表下方「可用资产类型」", Sample: "server", Width: 14},
	"ip_address":  {Note: "IPv4 / IPv6 / CIDR 网段 / 主机名", Sample: "192.168.1.10", Width: 18},
	"port":        {Note: "1–65535 的整数，留空表示未填写", Sample: "443", Width: 10},
	"hostname":    {Note: "主机名或域名，最多 128 字", Sample: "web-01.example.com", Width: 24},
	"os_type":     {Note: "操作系统，最多 64 字", Sample: "CentOS 7.9", Width: 18},
	"group":       {Note: "用 / 分隔的层级路径（最多 " + strconv.Itoa(model.MaxAssetGroupDepth) + " 层）；组不存在时可在导入确认页勾选「自动创建」", Sample: "总部/华东区/机房A", Width: 28},
	"importance":  {Note: "1–5 的整数，留空按 " + strconv.Itoa(int(model.ImportanceDefault)) + " 处理", Sample: "4", Width: 10},
	"owner":       {Note: "资产负责人，最多 64 字", Sample: "张三", Width: 12},
	"department":  {Note: "归属部门，最多 64 字", Sample: "运维部", Width: 14},
	"status":      {Note: "in_use / idle / offline / scrapped，或 在用 / 闲置 / 已下线 / 已报废；留空按 在用", Sample: "在用", Width: 16},
	"tags":        {Note: "多个标签用逗号分隔，最多 10 个", Sample: "核心,生产", Width: 18},
	"description": {Note: "备注，最多 512 字", Sample: "承载内网核心交换", Width: 32},
}

// assetStatusLabels 状态的中文别名。
//
// 用户不会去记 in_use 这种码，他会在表格里写「在用」。两个都认，
// 但**只认这几种明确的说法**——如果连「使用中」「正在用」都收，
// 这个字段迟早会变成一堆近义词的集合，而近义词之间的边界无人能说清。
var assetStatusLabels = map[string]model.AssetStatus{
	"在用":  model.AssetStatusInUse,
	"使用中": model.AssetStatusInUse,
	"闲置":  model.AssetStatusIdle,
	"已下线": model.AssetStatusOffline,
	"已报废": model.AssetStatusScrapped,
}

// ImportRowError 单行导入错误。
//
// Row 是**源文件里的行号**（含表头，从 1 开始），用户打开 Excel 就能
// 直接跳过去。Column 为空表示这是整行级的问题（例如重复）。
type ImportRowError struct {
	Row     int    `json:"row"`
	Column  string `json:"column"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// AssetImportPreview 导入预览结果。
type AssetImportPreview struct {
	FileName  string `json:"file_name"`
	Format    string `json:"format"`
	TotalRows int    `json:"total_rows"`
	ValidRows int    `json:"valid_rows"`
	ErrorRows int    `json:"error_rows"`
	// Errors 最多回传 maxImportPreviewErrors 条；ErrorRows 是真实总数。
	Errors []ImportRowError `json:"errors"`
	// TruncatedErrors 为 true 表示 Errors 被截断了（错误太多，看总数就够）
	TruncatedErrors bool `json:"truncated_errors"`
	// UnmatchedGroups 文件引用、系统中不存在、且**未**选择自动创建的
	// 资产组（可读路径，去重后按字典序）。非空会让 commit 失败。
	UnmatchedGroups []string `json:"unmatched_groups"`
	// GroupsToCreate 文件引用、系统中不存在、且**已**选择自动创建、
	// 因此会在 commit 时被建出来的资产组。
	GroupsToCreate []string `json:"groups_to_create"`
	// MissingColumns 当文件缺少必需列时列出它们。此时其它字段无意义。
	MissingColumns []string `json:"missing_columns"`
}

// AssetImportResult 导入结果。
type AssetImportResult struct {
	Imported      int `json:"imported"`
	CreatedGroups int `json:"created_groups"`
}

// parsedImportRow 解析后的一行。
type parsedImportRow struct {
	Number    int
	Asset     model.Asset
	GroupPath string
}

// importOutcome 解析结果，preview 与 commit 共用。
type importOutcome struct {
	preview    *AssetImportPreview
	rows       []parsedImportRow
	groupPaths []string

	// groupOnlyBlockedRows 统计「除了引用了不存在的资产组之外没有别的问题」
	// 的行数。commit 需要用它把这类行从 ErrorRows 里扣掉：问题只有一个明确
	// 的动作可解（勾选自动创建，或先把组建出来），应当报更具体的
	// ASSET_IMPORT_GROUP_NOT_FOUND，而不是笼统的 ASSET_IMPORT_HAS_ERRORS。
	groupOnlyBlockedRows int
}

// PreviewImport 解析并校验导入文件，不写入任何数据。
func (s *AssetService) PreviewImport(
	ctx context.Context, fileName string, data []byte, createMissingGroups bool,
) (*AssetImportPreview, error) {
	outcome, err := s.parseImport(ctx, fileName, data, createMissingGroups)
	if err != nil {
		return nil, err
	}
	return outcome.preview, nil
}

// CommitImport 校验并写入导入文件。
//
// 任一行不合格时**一条都不写**，失败分两种：
//   - 除了「引用了不存在的组」之外还有别的问题 → ASSET_IMPORT_HAS_ERRORS（409），
//     错误响应体里带完整的预览结果，前端可以直接渲染与预览阶段同样的错误表；
//   - 唯一的阻塞原因就是「组不存在且没选自动创建」→ ASSET_IMPORT_GROUP_NOT_FOUND（400），
//     这时用户只需要做一个动作（勾选自动创建或先建组），给具体码比给笼统的
//     行错误提示更有指向性。
func (s *AssetService) CommitImport(
	ctx context.Context, fileName string, data []byte, createMissingGroups bool,
	operator *auth.Principal, meta RequestMeta,
) (*AssetImportResult, error) {
	outcome, err := s.parseImport(ctx, fileName, data, createMissingGroups)
	if err != nil {
		return nil, err
	}
	if outcome.preview.ErrorRows-outcome.groupOnlyBlockedRows > 0 {
		return nil, errImportHasErrors(outcome.preview)
	}
	// 存在未匹配的组且用户没有选择自动创建：交给用户决定，不要擅自创建。
	// 擅自创建会往组织结构里塞进用户并不认可的层级，而删掉它们
	// 又得先确认里面没有资产 —— 是一个单向的麻烦。
	//
	// 走到这里意味着「没勾自动创建」是这批行唯一的阻塞原因（上面已经
	// 扣掉了 groupOnlyBlockedRows），所以可以给出这个更具体的码。
	// 反过来若先判 ErrorRows，这个码就永远不可达 —— 契约里列了却不会
	// 出现的错误码，比不写更糟。
	if len(outcome.preview.UnmatchedGroups) > 0 {
		return nil, errImportGroupNotFound(outcome.preview.UnmatchedGroups)
	}

	result := &AssetImportResult{}

	// 事务边界：建组 + 插资产必须同进同退。若分开提交，中途失败会留下
	// 一批「为了这次导入而建、但这次导入又没成功」的空组。
	err = s.repo.Transaction(ctx, func(txRepo *repository.Repository) error {
		groupIDs, created, err := s.ensureImportGroups(
			ctx, txRepo, outcome.groupPaths, createMissingGroups)
		if err != nil {
			return err
		}
		result.CreatedGroups = created

		assets := make([]model.Asset, 0, len(outcome.rows))
		for _, row := range outcome.rows {
			asset := row.Asset
			if row.GroupPath != "" {
				id, ok := groupIDs[row.GroupPath]
				if !ok {
					// 理论上不可达：parse 已确认全部路径都能解析。
					// 留这个分支是为了万一将来 parse 的判据改了，
					// 这里会明确失败，而不是把资产静默写成「未分组」。
					return errImportGroupNotFound([]string{row.GroupPath})
				}
				groupID := id
				asset.GroupID = &groupID
			}
			if operator != nil {
				creator := operator.UserID
				asset.CreatedBy = &creator
			}
			assets = append(assets, asset)
		}

		if len(assets) > 0 {
			if err := txRepo.Asset.BatchCreate(ctx, assets); err != nil {
				return err
			}
		}
		result.Imported = len(assets)
		return nil
	})
	if err != nil {
		var be *Error
		if errors.As(err, &be) {
			return nil, be
		}
		// 唯一索引兜底：并发下两个人同时导入同一份清单时，
		// 前置查重会双双通过，最终由 uk_assets_asset_no 拦下。
		if isDuplicateKey(err) {
			return nil, errAssetNoTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "导入资产失败", err)
	}

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetImport,
		"asset", "", map[string]any{
			"file_name":      fileName,
			"format":         outcome.preview.Format,
			"total_rows":     outcome.preview.TotalRows,
			"imported":       result.Imported,
			"created_groups": result.CreatedGroups,
		}))

	return result, nil
}

// ------------------------------------------------------------------ 模板

// 模板的两张工作表。
const (
	// ImportTemplateSheetName 数据表名。导入时只读第一张表，
	// 因此这张必须是数据表。
	ImportTemplateSheetName = "资产导入"
	// importGuideSheetName 说明表，用户填写时对着看。
	importGuideSheetName = "填写说明"
)

// ImportTemplateFileName 模板下载时的文件名。
const ImportTemplateFileName = "资产导入模板.xlsx"

// importTemplateTextColumns 模板数据表里强制为文本格式的列（Excel 列字母）。
//
// 资产编号与 IP 地址必须设成文本：不设的话 Excel 会把「00123」按数字存，
// 前导零在用户毫无察觉的情况下丢掉；IP 也可能被自动识别成日期。
//
// 这两个字母依赖 importColumns 的列序，因此由
// TestImportTemplateTextColumnLettersAreInSyncWithColumnOrder 守着——
// 调整列序却忘了改这里，在界面上完全看不出来，只会在用户那边表现为
// 「编号前面的 0 不见了」。
var importTemplateTextColumns = []string{"B", "D"}

// ImportTemplate 生成资产导入模板（xlsx 字节流）。
//
// 模板里只放表头，**不放示例数据行**。带示例行的模板看起来更贴心，但用户
// 很容易忘掉先删掉它，于是台账里凭空多出一条「示例资产」——那条记录看起来
// 完全正常（名称、类型、IP 都齐全），事后几乎不可能被发现，而且还会被算进
// 风险统计。所有示例统一放到第二张「填写说明」表里。
//
// 说明表同时列出当前**启用**的资产类型（码与名称），用户不必切到字典维护页
// 去抄码。停用的类型不列：列出来等于引导用户去用它，而校验会拒掉。
func (s *AssetService) ImportTemplate(ctx context.Context) ([]byte, error) {
	types, err := s.repo.Dictionary.List(ctx,
		[]model.DictionaryCategory{model.CategoryAssetType}, true)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "读取资产类型失败", err)
	}
	// 按码的字典序排，而不是沿用字典表本身的排序：字典表的顺序是管理员
	// 自定义的（用于下拉框），而这里是一张「查码对照表」，按码排更好找。
	sort.Slice(types, func(i, j int) bool { return types[i].Code < types[j].Code })

	headers := make([]string, 0, len(importColumns))
	widths := make([]float64, 0, len(importColumns))
	guide := make([][]string, 0, len(importColumns)+len(types)+4)

	for _, col := range importColumns {
		headers = append(headers, col.Header)
		widths = append(widths, importColumnGuides[col.Key].Width)

		meta := importColumnGuides[col.Key]
		guide = append(guide, []string{
			col.Header,
			requiredText(col.Required),
			meta.Note,
			meta.Sample,
		})
	}

	if len(types) > 0 {
		// 两张表之间留一个空行。Excel 里没有「分区标题」这种东西，
		// 一个空行是最直白的视觉分隔。
		guide = append(guide,
			[]string{"", "", "", ""},
			[]string{"可用资产类型（「资产类型」列填下面的码或名称都可以）", "", "", ""},
			[]string{"码", "名称", "说明", ""},
		)
		for _, t := range types {
			guide = append(guide, []string{t.Code, t.Name, t.Description, ""})
		}
	}

	sheets := []spreadsheet.SheetSpec{
		{
			Name:   ImportTemplateSheetName,
			Header: headers,
			// 表头之外不放任何行 —— 见函数注释里为什么
			Rows: [][]string{},
			// 资产编号与 IP 地址强制为文本，理由见 importTemplateTextColumns
			TextColumns: importTemplateTextColumns,
			Widths:      widths,
		},
		{
			Name:   importGuideSheetName,
			Header: []string{"列名/码", "是否必填", "填写说明", "示例/名称"},
			Rows:   guide,
			Widths: []float64{16, 10, 56, 26},
		},
	}

	data, err := spreadsheet.WriteXLSX(sheets)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "生成导入模板失败", err)
	}
	return data, nil
}

func requiredText(required bool) string {
	if required {
		return "必填"
	}
	return "选填"
}

// ------------------------------------------------------------------ 解析

// parseImport 是 preview 与 commit 共用的唯一解析与校验入口。
//
// 共用同一份实现是两阶段设计能够成立的前提：一旦分成两份，
// 「预览通过、提交失败」就会出现，而那会让用户彻底不再信任预览。
func (s *AssetService) parseImport(
	ctx context.Context, fileName string, data []byte, createMissingGroups bool,
) (*importOutcome, error) {
	sheet, err := spreadsheet.Read(data, spreadsheet.MaxRows)
	if err != nil {
		switch {
		case errors.Is(err, spreadsheet.ErrEmpty):
			return nil, errImportNoRows()
		case errors.Is(err, spreadsheet.ErrTooLarge):
			return nil, ErrImportFileTooLarge()
		case errors.Is(err, spreadsheet.ErrTooManyRows):
			return nil, errImportTooManyRows()
		default:
			return nil, errImportFormatInvalid(
				"文件无法解析，请确认是 .xlsx 或 .csv 格式且未损坏")
		}
	}

	preview := &AssetImportPreview{
		FileName:        fileName,
		Format:          string(sheet.Format),
		Errors:          []ImportRowError{},
		UnmatchedGroups: []string{},
		GroupsToCreate:  []string{},
		MissingColumns:  []string{},
	}

	colIndex, missing := mapImportColumns(sheet.Rows[0])
	if len(missing) > 0 {
		// 缺列是文件级问题：此时按列取值的逻辑对不上，继续逐行校验
		// 只会产出一堆「第 2 行 资产类型 为空」这种误导性错误。
		preview.MissingColumns = missing
		return nil, errImportMissingColumns(missing)
	}

	types, err := loadDictionaryMap(ctx, s.repo, model.CategoryAssetType)
	if err != nil {
		return nil, err
	}
	typeAliases := buildAssetTypeAliasIndex(types)

	groupIndex, err := loadGroupIndex(ctx, s.repo)
	if err != nil {
		return nil, err
	}

	existingNos, existingIdentities, err := s.loadExistingKeys(ctx, sheet, colIndex)
	if err != nil {
		return nil, err
	}

	// 文件内查重：键 → 首次出现的行号
	seenNos := make(map[string]int)
	seenIdentities := make(map[string]int)

	outcome := &importOutcome{preview: preview}
	referencedGroups := make(map[string]struct{})

	dataRows := sheet.Rows[1:]
	// 只有表头的文件必须在这里挡掉。spreadsheet.Read 的 ErrEmpty 判据是
	// 「有没有非空行」，而表头本身就是一行非空行，所以它不会报错——
	// 于是下面这个循环一次都不跑，预览返回「共 0 行、0 条错误、0 条合格」，
	// 用户看到一张空表却没有任何提示。commit 更糟：它会写 0 条并报成功。
	if len(dataRows) == 0 {
		return nil, errImportNoRows()
	}
	preview.TotalRows = len(dataRows)

	for _, row := range dataRows {
		parsed, errs := parseImportRow(row, colIndex, types, typeAliases)
		if len(errs) > 0 {
			preview.ErrorRows++
			appendImportErrors(preview, errs)
			// 逐格校验没过的行不参与查重：它的名称或 IP 可能是错的，
			// 拿一个错的值去比对只会产出第二层误导性错误。
			continue
		}

		// ---- 文件内 / 库内查重
		identity := repository.AssetIdentityKey(parsed.Asset.Name, parsed.Asset.IPAddress)

		if parsed.Asset.AssetNo != nil {
			no := *parsed.Asset.AssetNo
			if first, dup := seenNos[no]; dup {
				preview.ErrorRows++
				appendImportErrors(preview, []ImportRowError{{
					Row: row.Number, Column: "资产编号", Value: no,
					Message: "与第 " + strconv.Itoa(first) + " 行的资产编号重复",
				}})
				continue
			}
			if id, taken := existingNos[no]; taken {
				preview.ErrorRows++
				appendImportErrors(preview, []ImportRowError{{
					Row: row.Number, Column: "资产编号", Value: no,
					Message: "该资产编号已存在（资产 ID " + strconv.FormatUint(id, 10) + "）",
				}})
				continue
			}
			seenNos[no] = row.Number
		}

		if first, dup := seenIdentities[identity]; dup {
			preview.ErrorRows++
			appendImportErrors(preview, []ImportRowError{{
				Row: row.Number, Column: "资产名称", Value: parsed.Asset.Name,
				Message: "与第 " + strconv.Itoa(first) +
					" 行的「名称 + IP 地址」重复，同一份文件里不应有两条相同的资产",
			}})
			continue
		}
		if id, taken := existingIdentities[identity]; taken {
			preview.ErrorRows++
			appendImportErrors(preview, []ImportRowError{{
				Row: row.Number, Column: "资产名称", Value: parsed.Asset.Name,
				Message: "系统中已存在同名同 IP 的资产（资产 ID " +
					strconv.FormatUint(id, 10) + "）。重复导入同一份清单时会出现这个提示",
			}})
			continue
		}
		seenIdentities[identity] = row.Number

		// ---- 资产组
		if parsed.GroupPath != "" {
			if _, ok := groupIndex.byName[parsed.GroupPath]; !ok {
				referencedGroups[parsed.GroupPath] = struct{}{}
				if !createMissingGroups {
					preview.ErrorRows++
					// 能走到这里就说明这一行只栽在「组不存在」上：
					// 逐格校验与查重都已经放它过去了。记下来供 commit 区分。
					outcome.groupOnlyBlockedRows++
					appendImportErrors(preview, []ImportRowError{{
						Row: row.Number, Column: "资产组", Value: parsed.GroupPath,
						Message: "资产组不存在。请先在「资产分组」里创建它，" +
							"或在确认导入时勾选「自动创建缺失的资产组」",
					}})
					continue
				}
			}
		}

		preview.ValidRows++
		outcome.rows = append(outcome.rows, parsed)
	}

	// 已选择自动创建的组，只统计「确实还不存在」的那些——已经存在的
	// 不需要创建，列出来会让用户以为系统要多建一个同名的组。
	if createMissingGroups {
		preview.GroupsToCreate = sortedStringSet(referencedGroups)
	} else {
		preview.UnmatchedGroups = sortedStringSet(referencedGroups)
	}
	outcome.groupPaths = sortedStringSet(referencedGroups)

	return outcome, nil
}

// parseImportRow 逐格校验并构造资产。
//
// 刻意不挂在 AssetService 上：它不需要任何依赖（字典与别名表都是入参），
// 而「某一格为什么不合法」恰恰是导入功能最需要单测覆盖的部分。
// 带一个用不到的接收者会让这段逻辑必须搭一个 service 才能测。
func parseImportRow(
	row spreadsheet.Row,
	colIndex map[string]int,
	types map[string]model.Dictionary,
	typeAliases map[string]string,
) (parsedImportRow, []ImportRowError) {
	var errs []ImportRowError

	cell := func(key string) string {
		return cellAt(row, colIndex[key])
	}
	bad := func(column, value, message string) {
		errs = append(errs, ImportRowError{
			Row: row.Number, Column: column, Value: value, Message: message,
		})
	}

	parsed := parsedImportRow{Number: row.Number}
	asset := &parsed.Asset

	// ---- 资产名称
	name := cell("name")
	switch {
	case name == "":
		bad("资产名称", "", "资产名称为必填项")
	case len([]rune(name)) > assetNameMaxRunes:
		bad("资产名称", name, "不得超过 128 个字符")
	default:
		asset.Name = name
	}

	// ---- 资产编号
	if rawNo := cell("asset_no"); rawNo != "" {
		no, err := validateAssetNo(rawNo)
		if err != nil {
			bad("资产编号", rawNo, "格式不正确，只能包含字母、数字与 _ . - /，且以字母或数字开头")
		} else if no != "" {
			asset.AssetNo = &no
		}
	}

	// ---- 资产类型（码或中文名都认）
	rawType := cell("asset_type")
	if rawType == "" {
		bad("资产类型", "", "资产类型为必填项")
	} else if code, ok := resolveAssetTypeValue(types, typeAliases, rawType); !ok {
		bad("资产类型", rawType,
			"系统中不存在该资产类型。可填类型的码（如 server）或名称（如 服务器）")
	} else if !types[code].Enabled {
		bad("资产类型", rawType, "该资产类型已停用，不能用于新导入的资产")
	} else {
		asset.AssetType = code
	}

	// ---- IP 地址
	if rawIP := cell("ip_address"); rawIP != "" {
		if err := validateIPAddress(rawIP); err != nil {
			bad("IP 地址", rawIP,
				"格式不正确（可填 IPv4 / IPv6 / CIDR 网段 / 主机名）")
		} else {
			asset.IPAddress = rawIP
		}
	}

	// ---- 端口
	if rawPort := cell("port"); rawPort != "" {
		if port, err := parsePort(rawPort); err != nil {
			bad("端口", rawPort, "需为 1–65535 之间的整数")
		} else {
			asset.Port = &port
		}
	}

	// ---- 重要性
	if raw := cell("importance"); raw == "" {
		asset.Importance = model.ImportanceDefault
	} else if n, err := strconv.Atoi(raw); err != nil ||
		n < int(model.ImportanceMin) || n > int(model.ImportanceMax) {
		bad("重要性", raw, "需为 1–5 之间的整数，留空按 "+
			strconv.Itoa(int(model.ImportanceDefault))+" 处理")
	} else {
		asset.Importance = uint8(n)
	}

	// ---- 状态
	if raw := cell("status"); raw == "" {
		asset.Status = model.AssetStatusInUse
	} else if status, ok := resolveAssetStatusAlias(raw); ok {
		asset.Status = status
	} else {
		bad("状态", raw,
			"只能填 in_use / idle / offline / scrapped，或 在用 / 闲置 / 已下线 / 已报废")
	}

	// ---- 资产组
	if rawGroup := cell("group"); rawGroup != "" {
		normalized, ok := normalizeGroupPath(rawGroup)
		switch {
		case !ok:
			bad("资产组", rawGroup,
				"资产组路径不合法（形如 总部/华东区/机房A，最多 "+
					strconv.Itoa(model.MaxAssetGroupDepth)+" 层）")
		default:
			parsed.GroupPath = normalized
		}
	}

	// ---- 标签（中英文逗号、分号、顿号都当分隔符）
	if rawTags := cell("tags"); rawTags != "" {
		if tags, err := normalizeTags(splitTagCell(rawTags)); err != nil {
			bad("标签", rawTags, "标签不合法（单个不超过 32 字，最多 10 个，且不能含逗号）")
		} else {
			asset.Tags = strings.Join(tags, ",")
		}
	}

	// ---- 普通文本列
	asset.Hostname = trimTo(cell("hostname"), assetHostnameMaxRunes)
	asset.OSType = trimTo(cell("os_type"), assetOSTypeMaxRunes)
	asset.Owner = trimTo(cell("owner"), assetOwnerMaxRunes)
	asset.Department = trimTo(cell("department"), assetDepartmentMaxRunes)
	asset.Description = trimTo(cell("description"), assetDescriptionMaxRunes)

	return parsed, errs
}

// ------------------------------------------------------------------ 辅助

// mapImportColumns 把表头映射成「键 → 列下标」，并返回缺失的必需列。
//
// 按列名匹配而不是按位置：允许列顺序与模板不同，也允许存在模板之外的
// 额外列（直接忽略）。若按位置匹配，用户自己插一列「备注2」会让后面
// 所有列整体错位，而错位后的数据看起来完全合理——这类问题极难发现。
func mapImportColumns(header spreadsheet.Row) (map[string]int, []string) {
	index := make(map[string]int, len(importColumns))
	for _, col := range importColumns {
		index[col.Key] = -1
	}
	for i, cell := range header.Cells {
		name := strings.TrimSpace(cell)
		for _, col := range importColumns {
			// 重复列名取第一次出现的位置，与 Excel 的行为一致
			if col.Header == name && index[col.Key] < 0 {
				index[col.Key] = i
			}
		}
	}

	var missing []string
	for _, col := range importColumns {
		if col.Required && index[col.Key] < 0 {
			missing = append(missing, col.Header)
		}
	}
	return index, missing
}

// buildAssetTypeAliasIndex 构建「中文名 → 码」的别名表。
//
// 为什么需要一张显式的表而不是在使用处遍历 map：Go 的 map 遍历顺序是
// 随机的，若两个类型恰好同名（内置类型允许改名，用户完全可以改出重复名），
// 按名称解析的结果会在每次请求之间跳变。这里改成按码排序后取第一个，
// 并把重名的名称**标记为歧义**（不放进索引），于是这类输入会得到一个
// 明确的「不存在该类型」错误，而不是时而成功时而失败。
func buildAssetTypeAliasIndex(types map[string]model.Dictionary) map[string]string {
	codes := make([]string, 0, len(types))
	for code := range types {
		codes = append(codes, code)
	}
	sort.Strings(codes)

	ambiguous := make(map[string]struct{})
	alias := make(map[string]string, len(types))
	for _, code := range codes {
		name := types[code].Name
		if name == "" {
			continue
		}
		// 名称与某个码完全相同时不建别名：那会让「写码」与「写名」
		// 指向同一个项，虽然结果一样，但会掩盖用户真正的意图。
		if _, isCode := types[name]; isCode {
			continue
		}
		if _, dup := alias[name]; dup {
			ambiguous[name] = struct{}{}
			continue
		}
		alias[name] = code
	}
	for name := range ambiguous {
		delete(alias, name)
	}
	return alias
}

// resolveAssetTypeValue 把「码」或「中文名」解析成字典码。
//
// 认两种写法的理由很实际：模板里给的是码（server），但用户凭直觉
// 会写「服务器」。只认码会把最常见的一次性错误放大成一屏 500 条报错。
func resolveAssetTypeValue(
	types map[string]model.Dictionary, alias map[string]string, raw string,
) (string, bool) {
	if _, ok := types[raw]; ok {
		return raw, true
	}
	if code, ok := alias[raw]; ok {
		return code, true
	}
	return "", false
}

func resolveAssetStatusAlias(raw string) (model.AssetStatus, bool) {
	if s := model.AssetStatus(raw); s.Valid() {
		return s, true
	}
	s, ok := assetStatusLabels[raw]
	return s, ok
}

// parsePort 解析端口单元格。
//
// 入参保证已去除首尾空白（spreadsheet 层在读出单元格时就做了），
// 因此这里**不**再做一次 TrimSpace —— 留着会是永远走不到的死代码，
// 而「看起来能容忍空格」会诱使后来的调用方跳过自己的裁剪。
func parsePort(raw string) (uint16, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("端口超出范围")
	}
	return uint16(n), nil
}

// splitTagCell 拆分标签单元格。
//
// 同时接受英文逗号、中文逗号、分号与顿号：用户从别处粘贴过来的标签
// 什么分隔符都可能带，而只认一种只会让他看到「标签不合法」
// 却不知道原因。
func splitTagCell(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', '、':
			return true
		}
		return false
	})
}

// normalizeGroupPath 归一化资产组路径。
//
// 去掉首尾斜杠与每段两端空白，把连续斜杠折成一个。返回 false 表示
// 路径不合法：有空段、层级超限、或单段名过长。
func normalizeGroupPath(raw string) (string, bool) {
	s := strings.Trim(strings.TrimSpace(raw), "/")
	if s == "" {
		return "", false
	}
	parts := strings.Split(s, "/")
	if len(parts) > model.MaxAssetGroupDepth {
		return "", false
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		seg := strings.TrimSpace(p)
		if seg == "" {
			return "", false
		}
		if len([]rune(seg)) > assetGroupNameMaxRunes {
			return "", false
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/"), true
}

// appendImportErrors 追加错误，超过上限后只计数不再追加。
func appendImportErrors(preview *AssetImportPreview, errs []ImportRowError) {
	remain := maxImportPreviewErrors - len(preview.Errors)
	if remain <= 0 {
		preview.TruncatedErrors = true
		return
	}
	if remain >= len(errs) {
		preview.Errors = append(preview.Errors, errs...)
		return
	}
	preview.Errors = append(preview.Errors, errs[:remain]...)
	preview.TruncatedErrors = true
}

// loadExistingKeys 一次性取回库内已有的编号与「名称 + IP」索引。
//
// 两次查询而不是每行查一次：500 行逐行查重就是 1000 次往返。
func (s *AssetService) loadExistingKeys(
	ctx context.Context, sheet *spreadsheet.Sheet, colIndex map[string]int,
) (map[string]uint64, map[string]uint64, error) {
	noIdx, ipIdx := colIndex["asset_no"], colIndex["ip_address"]

	noSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})
	for _, row := range sheet.Rows[1:] {
		if v := cellAt(row, noIdx); v != "" {
			noSet[v] = struct{}{}
		}
		if v := cellAt(row, ipIdx); v != "" {
			ipSet[v] = struct{}{}
		}
	}

	nos := make([]string, 0, len(noSet))
	for v := range noSet {
		nos = append(nos, v)
	}
	ips := make([]string, 0, len(ipSet))
	for v := range ipSet {
		ips = append(ips, v)
	}

	existingNos, err := s.repo.Asset.ExistingAssetNos(ctx, nos)
	if err != nil {
		return nil, nil, wrapError(500, errcode.CodeInternal, "导入校验失败", err)
	}
	existingIdentities, err := s.repo.Asset.ExistingByNameAndIP(ctx, ips)
	if err != nil {
		return nil, nil, wrapError(500, errcode.CodeInternal, "导入校验失败", err)
	}
	return existingNos, existingIdentities, nil
}

func cellAt(row spreadsheet.Row, idx int) string {
	if idx < 0 || idx >= len(row.Cells) {
		return ""
	}
	return strings.TrimSpace(row.Cells[idx])
}

// ------------------------------------------------------------------ 组索引

// groupIndex 资产组的可读路径索引。
//
// 「可读路径」是「总部/华东区/机房A」这种按名称拼成的路径，
// 与数据库里的物化路径（/1/4/9/，按 ID 拼）不是一回事：
// 前者是用户在 Excel 里能看到、也愿意填的东西。
type groupIndex struct {
	byName map[string]uint64
	byID   map[uint64]model.AssetGroup
}

// loadGroupIndex 一次读取全部资产组并建立可读路径索引。
func loadGroupIndex(ctx context.Context, repo *repository.Repository) (*groupIndex, error) {
	groups, err := repo.AssetGroup.ListAll(ctx)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "读取资产组失败", err)
	}

	idx := &groupIndex{
		byName: make(map[string]uint64, len(groups)),
		byID:   make(map[uint64]model.AssetGroup, len(groups)),
	}
	for i := range groups {
		idx.byID[groups[i].ID] = groups[i]
	}

	// 单趟拼接可读路径，依赖 ListAll 按物化路径排序这一性质：
	// 父的路径永远是子的前缀，排序上父必然先出现。
	// 这里**不**用递归或重复上溯，否则 N 个组就要跑 N 次链式查找。
	readable := make(map[uint64]string, len(groups))
	for i := range groups {
		g := &groups[i]
		if g.ParentID == nil {
			readable[g.ID] = g.Name
		} else if parentPath, ok := readable[*g.ParentID]; ok {
			readable[g.ID] = parentPath + "/" + g.Name
		} else {
			// 父节点没先出现（说明排序前提被破坏，或数据里存在环）。
			// 退化成单段名：这个组仍然能被自己的名字定位，
			// 只是不带前缀。不 panic，也不静默丢弃。
			readable[g.ID] = g.Name
		}
		idx.byName[readable[g.ID]] = g.ID
	}
	return idx, nil
}

// ensureImportGroups 解析（必要时创建）导入引用的资产组。
//
// createMissing 为 false 时只做解析，缺失即报错。
// 返回 可读路径 → 组 ID 的映射，以及本次新建的组数量。
func (s *AssetService) ensureImportGroups(
	ctx context.Context, repo *repository.Repository,
	paths []string, createMissing bool,
) (map[string]uint64, int, error) {
	idx, err := loadGroupIndex(ctx, repo)
	if err != nil {
		return nil, 0, err
	}

	resolved := make(map[string]uint64, len(paths))
	created := 0
	var missing []string

	for _, path := range paths {
		if id, ok := idx.byName[path]; ok {
			resolved[path] = id
			continue
		}
		if !createMissing {
			missing = append(missing, path)
			continue
		}
		id, n, err := idx.ensure(ctx, repo, path)
		if err != nil {
			var be *Error
			if errors.As(err, &be) {
				return nil, created, be
			}
			if isDuplicateKey(err) {
				return nil, created, errAssetGroupNameTaken()
			}
			return nil, created, wrapError(500, errcode.CodeInternal,
				"创建缺失的资产组失败", err)
		}
		resolved[path] = id
		created += n
	}

	if len(missing) > 0 {
		return nil, created, errImportGroupNotFound(missing)
	}
	return resolved, created, nil
}

// ensure 确保该可读路径存在，返回末级组 ID 与本次新建的数量。
//
// 逐段创建：文件里写「总部/华东区/机房A」而三级都不存在时，
// 会把三层一并建出来。只建末级是不可能的——它的父级还不存在。
func (idx *groupIndex) ensure(
	ctx context.Context, repo *repository.Repository, path string,
) (uint64, int, error) {
	parts := strings.Split(path, "/")
	created := 0

	var parentID *uint64
	var parentMaterialized string
	current := ""

	for depth, seg := range parts {
		if depth > int(maxAssetGroupDepthValue) {
			return 0, created, errAssetGroupDepthExceeded()
		}
		if current == "" {
			current = seg
		} else {
			current += "/" + seg
		}

		if id, ok := idx.byName[current]; ok {
			existing := idx.byID[id]
			gid := id
			parentID = &gid
			parentMaterialized = existing.Path
			continue
		}

		g := &model.AssetGroup{
			ParentID:    parentID,
			Name:        seg,
			Depth:       uint32(depth),
			Description: "由资产导入自动创建",
		}
		if err := repo.AssetGroup.Create(ctx, g, parentMaterialized); err != nil {
			return 0, created, err
		}

		idx.byName[current] = g.ID
		idx.byID[g.ID] = *g
		gid := g.ID
		parentID = &gid
		parentMaterialized = g.Path
		created++
	}

	if parentID == nil {
		return 0, created, errAssetGroupNotFound()
	}
	return *parentID, created, nil
}

// sortedStringSet 把集合转成排好序的切片。
//
// 排序有两个好处：响应内容稳定（便于 diff 与断言），
// 以及错误提示里的组名顺序对用户是可预期的。
// 空集合返回空切片而不是 nil，保证 JSON 里是 [] 而非 null。
func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
