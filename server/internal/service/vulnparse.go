package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/filestore"
	"secrisk/server/internal/pkg/reportparser"
	"secrisk/server/internal/repository"
)

// VulnImportTemplate 生成漏洞导入模板（静态内容，无数据库依赖）。
func VulnImportTemplate() ([]byte, error) {
	data, err := reportparser.ExcelTemplate()
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "生成漏洞导入模板失败", err)
	}
	return data, nil
}

// VulnParsePreview 解析预览结果。
type VulnParsePreview struct {
	FileID   uint64 `json:"file_id"`
	FileName string `json:"file_name"`
	Format   string `json:"format"`
	Total    int    `json:"total"`
	// UnmatchedIPs 预览中解析出、但资产台账里没有的 IP（去重按字典序）。
	// 仅供参考，不阻塞 commit——「先传报告、后补资产」是正常顺序。
	UnmatchedIPs []string `json:"unmatched_ips"`
	MatchedCount int      `json:"matched_count"`
	// ErrorRows / Errors Excel 路径的行级错误，口径与资产导入一致。
	ErrorRows int                     `json:"error_rows"`
	Errors    []reportparser.RowError `json:"errors"`
	// MissingColumns 缺失的必需列。非空时其它字段无意义。
	MissingColumns []string `json:"missing_columns"`
}

// VulnParseResult 解析入库结果。
type VulnParseResult struct {
	FileID       uint64 `json:"file_id"`
	Imported     int    `json:"imported"`
	LinkedAuto   int    `json:"linked_auto"`
	UnmatchedIPs int    `json:"unmatched_ips"`
}

// PreviewParse 解析文件但不写入任何数据。
//
// 同一个文件可以反复预览（比如先补了几条资产再看匹配情况），
// 预览不改变 parse_status，也不产生审计——它只读。
func (s *FileService) PreviewParse(ctx context.Context, fileID uint64) (*VulnParsePreview, error) {
	outcome, err := s.parseFile(ctx, fileID)
	if err != nil {
		return nil, err
	}
	return outcome.preview, nil
}

// CommitParse 解析并把漏洞写入数据库。
//
// 与资产导入同一个铁律：**commit 重新解析重新校验，不复用 preview 结果**
// ——服务端不持有导入会话状态。预览之后台账可能变了（新资产上线，
// 原来匹配不上的 IP 现在能匹配了），重新解析恰恰能让这种改善生效。
//
// 原子性：任一行不合格一条不写；两个并发 commit 由 MarkParsed 的
// `WHERE parse_status = 'unparsed'` 裁决，后到者得 FILE_ALREADY_PARSED。
func (s *FileService) CommitParse(
	ctx context.Context, fileID uint64,
	principal *auth.Principal, meta RequestMeta,
) (*VulnParseResult, error) {
	outcome, err := s.parseFile(ctx, fileID)
	if err != nil {
		return nil, err
	}
	preview := outcome.preview

	// 有行级错误：409，一条不写，data 带完整预览（与资产导入同构）。
	if preview.ErrorRows > 0 {
		return nil, errVulnHasErrors(preview)
	}
	if len(preview.MissingColumns) > 0 {
		return nil, errVulnMissingColumns(preview.MissingColumns)
	}
	if len(outcome.vulns) == 0 {
		return nil, errVulnNoRows()
	}

	// ---- 事务：写漏洞 → 自动关联 → 标记文件已解析 ----
	var imported int
	var linkedAuto int64
	var unmatchedIPs int

	txErr := s.repo.Transaction(ctx, func(tx *repository.Repository) error {
		// MarkParsed 先行：两个并发 commit 只有一个能把状态从
		// unparsed 改走。把它放在漏洞写入之前，输家在写任何数据
		// 之前就退出，而不是写完一半才发现。
		rows, err := tx.ScanFile.MarkParsed(ctx, fileID, outcome.format, uint32(len(outcome.vulns)))
		if err != nil {
			return fmt.Errorf("更新文件解析状态失败: %w", err)
		}
		if rows == 0 {
			// 并发输家：另一个 commit 已把状态改走。直接返回业务错误，
			// 事务随之回滚，本请求一条数据都没写。
			return errFileAlreadyParsed()
		}

		records := make([]model.Vulnerability, len(outcome.vulns))
		for i, v := range outcome.vulns {
			desc := v.Description
			sol := v.Solution
			records[i] = model.Vulnerability{
				SourceFileID: &fileID,
				Title:        v.Title,
				CVEIDs:       strings.Join(v.CVEIDs, ","),
				SeverityRaw:  v.SeverityRaw,
				Severity:     v.Severity,
				Description:  ptrOrNil(desc),
				Solution:     ptrOrNil(sol),
				HostIP:       v.HostIP,
				Port:         v.Port,
				Protocol:     v.Protocol,
				Service:      v.Service,
			}
			if principal != nil {
				records[i].CreatedBy = &principal.UserID
			}
		}
		if err := tx.Vuln.CreateInBatches(ctx, records, 500); err != nil {
			return fmt.Errorf("批量写入漏洞失败: %w", err)
		}
		imported = len(records)

		// 自动关联：按 host_ip 精确匹配资产。同 IP 多资产时全部挂上
		// （一条漏洞确实同时影响同 IP 的多个资产）。
		ipSet := make(map[string]struct{})
		for i := range records {
			if records[i].HostIP != "" {
				ipSet[records[i].HostIP] = struct{}{}
			}
		}
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		assetMap, err := tx.Vuln.FindAssetIDsByIPs(ctx, ips)
		if err != nil {
			return fmt.Errorf("查询待关联资产失败: %w", err)
		}

		var links []model.VulnAssetLink
		for i := range records {
			if records[i].HostIP == "" {
				continue
			}
			assetIDs, ok := assetMap[records[i].HostIP]
			if !ok {
				unmatchedIPs++
				continue
			}
			for _, assetID := range assetIDs {
				link := model.VulnAssetLink{
					VulnID:    records[i].ID,
					AssetID:   assetID,
					MatchedBy: model.VulnLinkAuto,
				}
				if principal != nil {
					link.CreatedBy = &principal.UserID
				}
				links = append(links, link)
			}
		}
		linkedAuto, err = tx.Vuln.InsertLinksIgnore(ctx, links)
		if err != nil {
			return fmt.Errorf("写入自动关联失败: %w", err)
		}
		return nil
	})
	if txErr != nil {
		// 事务闭包返回的业务错误（如 FILE_ALREADY_PARSED）会被原样带回，
		// AsError 识别不出 *Error 的才折叠成 500。
		var svcErr *Error
		if errors.As(txErr, &svcErr) {
			return nil, svcErr
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "解析入库失败", txErr)
	}

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionFileParse, "scan_file", fmt.Sprintf("%d", fileID),
		map[string]any{
			"file_name":   outcome.file.OriginalName,
			"format":      string(outcome.format),
			"imported":    imported,
			"linked_auto": linkedAuto,
			"total_vulns": len(outcome.vulns),
		}))

	return &VulnParseResult{
		FileID:       fileID,
		Imported:     imported,
		LinkedAuto:   int(linkedAuto),
		UnmatchedIPs: unmatchedIPs,
	}, nil
}

// errRollback 已废除：业务错误直接从事务闭包返回，由 GORM 原样带回。

// parsedFile 解析一个文件的完整中间结果。
type parsedFile struct {
	file    *model.ScanFile
	format  model.ScanFileFormat
	vulns   []reportparser.ParsedVuln
	preview *VulnParsePreview
}

// parseFile 读取存储文件并解析，preview 与 commit 共用。
func (s *FileService) parseFile(ctx context.Context, fileID uint64) (*parsedFile, error) {
	f, err := s.findFile(ctx, fileID)
	if err != nil {
		return nil, err
	}
	if f.ParseStatus == model.ScanParseParsed {
		return nil, errFileAlreadyParsed()
	}

	rc, err := s.store.Open(f.StoragePath)
	if err != nil {
		if errors.Is(err, filestore.ErrNotFound) {
			return nil, errFileNotFound()
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取文件失败", err)
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取文件失败", err)
	}

	res, err := reportparser.Parse(data)
	if err != nil {
		// 解析失败：把失败状态留在文件上，用户修好文件后可以重新上传
		// （或对可重试的错误重新预览）。失败原因进日志，不回显给客户端。
		_ = s.repo.ScanFile.MarkFailed(ctx, fileID, reportparser.DetectFormat(data))
		s.logger.Warn("扫描报告解析失败",
			"scan_file_id", fileID, "file_name", f.OriginalName, "err", err)
		switch {
		case errors.Is(err, reportparser.ErrNoVulns):
			return nil, errVulnNoRows()
		case errors.Is(err, reportparser.ErrTooManyVulns):
			return nil, errVulnTooMany()
		case errors.Is(err, reportparser.ErrMalformed):
			return nil, errFileFormatUnknown()
		default:
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "解析报告失败", err)
		}
	}

	// 匹配统计：预览需要让用户看到「有多少条能自动挂上资产」。
	//
	// 计数口径是**漏洞条数**而不是 IP 个数：commit 返回的 linked_auto 也是
	// 条数，两者必须同口径——否则同一个文件在预览里显示「可关联 2」、
	// 提交后却报「自动关联 4 条」，用户只会以为哪里算错了。
	// 未匹配的 IP 仍然按 IP 去重列出（那是「还有哪些主机要补进台账」的
	// 待办清单，同一个 IP 出现 20 次没有意义）。
	ips := make([]string, 0, 16)
	seen := make(map[string]struct{})
	for _, v := range res.Vulns {
		if v.HostIP != "" {
			if _, ok := seen[v.HostIP]; !ok {
				seen[v.HostIP] = struct{}{}
				ips = append(ips, v.HostIP)
			}
		}
	}
	assetMap, err := s.repo.Vuln.FindAssetIDsByIPs(ctx, ips)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询资产匹配失败", err)
	}
	matched := 0
	unmatchedSet := make(map[string]struct{})
	for _, v := range res.Vulns {
		if v.HostIP == "" {
			continue
		}
		if ids, ok := assetMap[v.HostIP]; ok && len(ids) > 0 {
			matched++
		} else {
			unmatchedSet[v.HostIP] = struct{}{}
		}
	}
	unmatched := make([]string, 0, len(unmatchedSet))
	for ip := range unmatchedSet {
		unmatched = append(unmatched, ip)
	}
	sort.Strings(unmatched)

	preview := &VulnParsePreview{
		FileID:         fileID,
		FileName:       f.OriginalName,
		Format:         string(res.Format),
		Total:          len(res.Vulns),
		UnmatchedIPs:   unmatched,
		MatchedCount:   matched,
		ErrorRows:      len(res.Errors),
		Errors:         res.Errors,
		MissingColumns: res.MissingColumns,
	}
	return &parsedFile{file: f, format: res.Format, vulns: res.Vulns, preview: preview}, nil
}

// ptrOrNil 空串转 nil（TEXT 列的空串与 NULL 语义统一为 NULL）。
func ptrOrNil(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}
