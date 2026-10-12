// Package service 承载业务逻辑。
//
// 分层边界：
//   - handler  只负责参数绑定、调用 service、把结果写成响应
//   - service  业务规则、事务边界、审计落点，不碰 gin.Context
//   - repository 数据访问，唯一允许出现 SQL 的层
//
// service 不依赖 gin，是刻意的：这样业务规则可以在纯 Go 测试里验证，
// 不必为了测一条「最后一个管理员不能被移除」的规则去搭一个 HTTP 服务。
package service

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/reportparser"
	"secrisk/server/internal/pkg/spreadsheet"
)

// Error 业务错误。
//
// 携带错误码与 HTTP 状态码，让 handler 层不必为每个错误再写一遍映射；
// 同时也保证「对外文案」与「对内原因」分离——Err 只进日志，不回显给客户端，
// 避免数据库错误信息泄漏表结构与 SQL 片段。
type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	Err        error
	// Data 可选的结构化明细，会作为响应信封的 data 字段下发。
	//
	// 绝大多数错误不需要它——一句 message 就够了。它存在的理由是
	// **批量导入**：一份 500 行的文件里有 7 行不合格时，「导入失败」
	// 四个字毫无帮助，必须把「第几行、哪一列、什么值、为什么不合法」
	// 一并给出去。把这些塞进 message 会变成一段没法解析的散文。
	Data any
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap 支持 errors.Is / errors.As 向下追溯。
func (e *Error) Unwrap() error { return e.Err }

// newError 构造业务错误。
func newError(status int, code, message string) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status}
}

// newErrorWithData 构造带结构化明细的业务错误。
func newErrorWithData(status int, code, message string, data any) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status, Data: data}
}

// wrapError 包装底层错误，保留原因供日志记录。
func wrapError(status int, code, message string, err error) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status, Err: err}
}

// AsError 把任意错误归一化为 *Error。
//
// 非业务错误一律折叠成 500，且对外只给通用文案——
// 内部错误细节（SQL、文件路径、栈信息）不应对客户端可见。
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return wrapError(http.StatusInternalServerError, errcode.CodeInternal,
		"服务器内部错误，请稍后重试", err)
}

// ------------------------------------------------------------------ 认证错误

func errInvalidCredentials() *Error {
	return newError(http.StatusUnauthorized, errcode.CodeInvalidCredentials, "用户名或密码错误")
}

func errAccountDisabled() *Error {
	return newError(http.StatusForbidden, errcode.CodeAccountDisabled, "账号已被禁用，请联系管理员")
}

func errAccountLocked(until time.Time) *Error {
	return newError(http.StatusLocked, errcode.CodeAccountLocked,
		fmt.Sprintf("账号已被临时锁定，请于 %s 之后重试", until.Format("2006-01-02 15:04:05")))
}

func errTokenInvalid() *Error {
	return newError(http.StatusUnauthorized, errcode.CodeTokenInvalid, "登录状态无效，请重新登录")
}

func errTokenExpired() *Error {
	return newError(http.StatusUnauthorized, errcode.CodeTokenExpired, "登录状态已过期")
}

func errPasswordWeak(reason string) *Error {
	return newError(http.StatusBadRequest, errcode.CodePasswordWeak, reason)
}

func errPasswordMismatch() *Error {
	return newError(http.StatusBadRequest, errcode.CodePasswordMismatch, "原密码不正确")
}

func errPasswordUnchanged() *Error {
	return newError(http.StatusBadRequest, errcode.CodePasswordUnchanged, "新密码不能与原密码相同")
}

// ------------------------------------------------------------------ 用户错误

func errUserNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeNotFound, "用户不存在")
}

func errUsernameTaken() *Error {
	return newError(http.StatusConflict, errcode.CodeUsernameTaken, "该登录名已被占用")
}

func errEmailTaken() *Error {
	return newError(http.StatusConflict, errcode.CodeEmailTaken, "该邮箱已被占用")
}

func errLastAdmin() *Error {
	return newError(http.StatusConflict, errcode.CodeLastAdmin,
		"系统中至少需要保留一名启用的管理员，操作已阻止")
}

func errSelfOperation(reason string) *Error {
	return newError(http.StatusConflict, errcode.CodeSelfOperation, reason)
}

func errRoleNotAssignable() *Error {
	return newError(http.StatusBadRequest, errcode.CodeRoleNotAssignable, "指定的角色不存在")
}

// ------------------------------------------------------------------ 资产错误

func errAssetNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeAssetNotFound, "资产不存在")
}

func errAssetNoTaken() *Error {
	return newError(http.StatusConflict, errcode.CodeAssetNoTaken, "该资产编号已被占用")
}

// errAssetTypeUnknown 资产类型不在字典中，或已被停用。
//
// 与「参数格式错误」分开：这是「字典里没有这个类型」，正确的下一步是
// 去字典维护页补一个，而不是让用户反复修改输入。
func errAssetTypeUnknown(code string) *Error {
	if code == "" {
		return newError(http.StatusBadRequest, errcode.CodeAssetTypeUnknown, "资产类型不能为空")
	}
	return newError(http.StatusBadRequest, errcode.CodeAssetTypeUnknown,
		fmt.Sprintf("资产类型「%s」不存在或已停用", code))
}

func errAssetGroupNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeAssetGroupNotFound, "资产组不存在")
}

func errAssetGroupNameTaken() *Error {
	return newError(http.StatusConflict, errcode.CodeAssetGroupNameTaken,
		"同一父组下已存在同名资产组")
}

func errAssetGroupHasChildren() *Error {
	return newError(http.StatusConflict, errcode.CodeAssetGroupHasChildren,
		"该资产组下仍有子组，请先删除或移走子组")
}

func errAssetGroupHasAssets(n int64) *Error {
	return newError(http.StatusConflict, errcode.CodeAssetGroupHasAssets,
		fmt.Sprintf("该资产组（含子组）下仍有 %d 条资产，请先移走或删除它们", n))
}

func errAssetGroupCycle() *Error {
	return newError(http.StatusBadRequest, errcode.CodeAssetGroupCycle,
		"不能把资产组移动到它自己的子组之下")
}

func errAssetGroupDepthExceeded() *Error {
	return newError(http.StatusBadRequest, errcode.CodeAssetGroupDepthExceeded,
		fmt.Sprintf("资产组层级最多 %d 层", model.MaxAssetGroupDepth))
}

// ------------------------------------------------------------------ 导入错误

// 这两个是**传输层事实**，因此导出给 handler 使用。
//
// 「请求里根本没有 file 字段」与「请求体超过上限」都发生在拿到字节之前，
// 服务层只收到 []byte，无从判断。让 handler 自己拼一个 INVALID_PARAM 也能
// 跑通，但错误码体系里的 ASSET_IMPORT_FILE_MISSING / FILE_TOO_LARGE 就
// 永远不会被返回 —— 契约里列着、实际拿不到的码，比没有更误导。
func ErrImportFileMissing() *Error {
	return newError(http.StatusBadRequest, errcode.CodeImportFileMissing,
		"请选择要导入的文件")
}

// ErrImportFileTooLarge 文件体积超过上限。
func ErrImportFileTooLarge() *Error {
	return newError(http.StatusBadRequest, errcode.CodeImportFileTooLarge,
		fmt.Sprintf("文件不得超过 %d MB", spreadsheet.MaxFileSize>>20))
}

func errImportFormatInvalid(reason string) *Error {
	return newError(http.StatusBadRequest, errcode.CodeImportFormatInvalid, reason)
}

func errImportMissingColumns(columns []string) *Error {
	return newError(http.StatusBadRequest, errcode.CodeImportMissingColumns,
		"文件缺少必需列："+strings.Join(columns, "、")+"。请先下载最新模板")
}

func errImportNoRows() *Error {
	return newError(http.StatusBadRequest, errcode.CodeImportNoRows,
		"文件里没有可导入的数据行")
}

func errImportTooManyRows() *Error {
	return newError(http.StatusBadRequest, errcode.CodeImportTooManyRows,
		fmt.Sprintf("单次导入最多 %d 行", spreadsheet.MaxRows))
}

// errImportGroupNotFound commit 时文件引用了不存在的资产组，
// 而调用方没有选择「自动创建」。
func errImportGroupNotFound(names []string) *Error {
	// 只列前若干个：一份文件里可能引用了几十个不存在的组，
	// 全量拼进 message 会变成一屏乱码。前端应当展示 data 里的完整列表。
	const maxInline = 5
	shown := names
	suffix := ""
	if len(names) > maxInline {
		shown = names[:maxInline]
		suffix = fmt.Sprintf(" 等 %d 个", len(names))
	}
	return newError(http.StatusBadRequest, errcode.CodeImportGroupNotFound,
		"以下资产组不存在，请先创建，或勾选「自动创建缺失的资产组」："+
			strings.Join(shown, "、")+suffix)
}

// errImportHasErrors 导入内容存在不合格的行，**整批未写入**。
//
// 这里把完整的预览结果挂进 Data：前端要能直接渲染出与预览阶段
// 同样的错误表格，而不是只弹一句「导入失败」。带 Data 的错误响应
// 在契约里由 ErrorDetailEnvelope 描述。
func errImportHasErrors(preview any) *Error {
	return newErrorWithData(http.StatusConflict, errcode.CodeImportHasErrors,
		"文件中存在不合格的行，本次未导入任何数据；请修正后重新提交", preview)
}

// --------------------------------------------------------------- 字典错误

func errDictionaryNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeDictionaryNotFound, "字典项不存在")
}

func errDictionaryCategoryInvalid() *Error {
	return newError(http.StatusBadRequest, errcode.CodeDictionaryCategoryInvalid,
		"字典类别非法，只能是 asset_type / threat / vulnerability / measure")
}

func errDictionaryCodeTaken() *Error {
	return newError(http.StatusConflict, errcode.CodeDictionaryCodeTaken,
		"同一类别下已存在相同的码")
}

// errDictionaryCodeImmutable 字典码创建后不可修改。
//
// 这条规则的存在理由：资产表按 code 引用字典（assets.asset_type 存的就是码）。
// 允许改码会让历史资产瞬间指不到任何类型，而且没有任何报错——
// 资产列表里的「资产类型」列会直接变成空白。
func errDictionaryCodeImmutable() *Error {
	return newError(http.StatusBadRequest, errcode.CodeDictionaryCodeImmutable,
		"字典码创建后不可修改（资产按码引用它）。如需改名请改「名称」")
}

func errDictionaryBuiltinReadonly() *Error {
	return newError(http.StatusConflict, errcode.CodeDictionaryBuiltinReadonly,
		"内置字典项不允许删除。如需停用请关闭「启用」开关")
}

func errDictionaryInUse(n int64) *Error {
	return newError(http.StatusConflict, errcode.CodeDictionaryInUse,
		fmt.Sprintf("仍有 %d 条资产在使用该字典项，不能删除。如需停用请关闭「启用」开关", n))
}

// ------------------------------------------------------------- 文件与解析错误

func errFileNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeFileNotFound, "文件不存在或已被删除")
}

// 这两个是**传输层事实**，因此导出给 handler 使用（理由见
// ErrImportFileMissing）——「请求里没有 file 字段」与「请求体超限」
// 都发生在拿到字节之前，服务层无从判断。
func ErrFileMissing() *Error {
	return newError(http.StatusBadRequest, errcode.CodeFileTypeRejected,
		"请选择要上传的文件")
}

func ErrFileTooLarge() *Error {
	return newError(http.StatusRequestEntityTooLarge, errcode.CodeFileTooLarge,
		fmt.Sprintf("文件不得超过 %d MB", UploadMaxFileBytes>>20))
}

func errFileTypeRejected(reason string) *Error {
	return newError(http.StatusBadRequest, errcode.CodeFileTypeRejected,
		"文件类型校验未通过："+reason)
}

func errFileTooLarge(max int64) *Error {
	return newError(http.StatusRequestEntityTooLarge, errcode.CodeFileTooLarge,
		fmt.Sprintf("文件不得超过 %d MB", max>>20))
}

func errFileAlreadyParsed() *Error {
	return newError(http.StatusConflict, errcode.CodeFileAlreadyParsed,
		"该文件已解析入库，不能重复提交。请先删除已有漏洞（或强制删除文件）再重新解析")
}

func errFileInUse(vulnCount int64) *Error {
	return newError(http.StatusConflict, errcode.CodeFileInUse,
		fmt.Sprintf("该文件解析出的 %d 条漏洞仍存在，不能删除。"+
			"确认要一并删除这些漏洞时请勾选「强制删除」", vulnCount))
}

func errFileFormatUnknown() *Error {
	return newError(http.StatusUnsupportedMediaType, errcode.CodeFileFormatUnknown,
		"无法识别的报告格式，支持 Nessus XML / OpenVAS XML / 通用表格")
}

// errVulnHasErrors 解析结果存在不合格条目，**整批未写入**。
// data 带完整预览，前端直接渲染与预览阶段同样的错误表。
func errVulnHasErrors(preview any) *Error {
	return newErrorWithData(http.StatusConflict, errcode.CodeVulnHasErrors,
		"文件中存在不合格的条目，本次未写入任何数据；请修正后重新提交", preview)
}

func errVulnMissingColumns(missing []string) *Error {
	return newError(http.StatusBadRequest, errcode.CodeVulnMissingColumns,
		"文件缺少必需列："+strings.Join(missing, "、")+"。请先下载最新模板")
}

func errVulnNoRows() *Error {
	return newError(http.StatusBadRequest, errcode.CodeVulnNoRows,
		"文件里没有可解析出的漏洞条目")
}

func errVulnTooMany() *Error {
	return newError(http.StatusBadRequest, errcode.CodeVulnTooMany,
		fmt.Sprintf("单个报告最多包含 %d 条漏洞", reportparser.MaxVulns))
}

func errVulnNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeVulnNotFound, "漏洞不存在")
}

// ------------------------------------------------------------- 整改跟踪错误

func errRemediationNotFound() *Error {
	return newError(http.StatusNotFound, errcode.CodeRemediationNotFound, "整改单不存在或已被删除")
}

// errRemediationDuplicateActive 同一 (资产, 漏洞) 已有未闭环单。
//
// 文案里点明「已有一张未闭环的单」而不是「重复」：用户需要知道下一步是
// 去找那张单子，而不是改输入重试。
func errRemediationDuplicateActive() *Error {
	return newError(http.StatusConflict, errcode.CodeRemediationDuplicateActive,
		"该资产上的这个漏洞已有一张未闭环的整改单，请直接处理那张单子")
}

func errRemediationStatusInvalid(raw string) *Error {
	if raw == "" {
		return newError(http.StatusBadRequest, errcode.CodeRemediationStatusInvalid, "状态不能为空")
	}
	return newError(http.StatusBadRequest, errcode.CodeRemediationStatusInvalid,
		fmt.Sprintf("状态「%s」不是合法取值", raw))
}

// errRemediationTransitionInvalid 非法流转。
//
// 文案里带上「当前状态 + 允许的下一步」：状态机的边有九条，
// 用户记不住，而错误信息是最该给出答案的地方。
func errRemediationTransitionInvalid(from, to string, allowed []string) *Error {
	next := "不可再流转（终态）"
	if len(allowed) > 0 {
		next = "可流转到：" + strings.Join(allowed, "、")
	}
	return newError(http.StatusConflict, errcode.CodeRemediationTransitionInvalid,
		fmt.Sprintf("不能从「%s」流转到「%s」。当前%s", from, to, next))
}

func errRemediationNoteRequired(to string) *Error {
	return newError(http.StatusBadRequest, errcode.CodeRemediationNoteRequired,
		"流转到「"+to+"」时必须填写说明（结论或理由），否则这次变更事后无法解释")
}

func errRemediationDeleteForbidden(reason string) *Error {
	return newError(http.StatusConflict, errcode.CodeRemediationDeleteForbidden, reason)
}

func errRemediationBatchTooLarge(matched, max int) *Error {
	return newError(http.StatusBadRequest, errcode.CodeRemediationBatchTooLarge,
		fmt.Sprintf("本次命中的风险项有 %d 条，超过单次建单上限 %d 条。"+
			"请按更高的等级筛选后分批建单", matched, max))
}

func errRemediationBatchEmpty() *Error {
	return newError(http.StatusConflict, errcode.CodeRemediationBatchEmpty,
		"按当前条件没有可建单的风险项：该评估可能尚未计算，或所选等级下确实没有条目")
}
