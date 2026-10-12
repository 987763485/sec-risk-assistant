package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/intelfeed"
	"secrisk/server/internal/pkg/optional"
	"secrisk/server/internal/repository"
)

// 集成字段长度上限，与迁移 000008 的列宽一一对应。
//
// 在服务层拦一道而不是让 MySQL 去截断：MySQL 非严格模式下会**静默截断**
// 超长字符串，用户填了一长串地址、保存后只剩前半段，而且没有任何提示。
const (
	integrationNameMaxRunes          = 64
	integrationBaseURLMaxRunes       = 255
	integrationCredentialEnvMaxRunes = 64
)

const (
	// integrationMaxCVEsPerFetch 单次拉取的 CVE 条数上限。
	//
	// 一条漏洞理论上可以挂很多 CVE（`cve_ids` 是 512 字符的逗号分隔串）。
	// 不设上限意味着用户点一次「拉取」会向上游连发几十个请求——
	// 对 NVD 而言必然撞上 30 秒 5 次的限流，然后全部失败。
	// 与其让他看着一片红，不如让他先明确指定要拉哪一个。
	integrationMaxCVEsPerFetch = 5

	// credentialEnvPrefix 凭据环境变量名允许的**唯一**前缀。
	//
	// ⚠️ 这个前缀是安全边界，不是命名规范。理由见
	// credentialEnvAllowed 的注释。
	credentialEnvPrefix = "SR_INTEL_"

	// integrationRawJSONMaxBytes raw_json 落库上限。
	//
	// 适配器已经用 io.LimitReader 把上游响应限制在 2 MiB 以内，
	// 但那仍然是「一行的某个字段」能膨胀到的尺寸；64 KB 已足够保留
	// 一个 CVE 文档的全部关键字段供追溯。
	integrationRawJSONMaxBytes = 64 << 10

	// integrationDescMaxRunes 描述文本落库上限（按 rune 计）。
	integrationDescMaxRunes = 8000

	// integrationTitleMaxRunes 标题落库上限（VARCHAR(255)）。
	integrationTitleMaxRunes = 255

	// integrationLastErrorMaxRunes 运行态里失败原因的长度上限（VARCHAR(255)）。
	integrationLastErrorMaxRunes = 255
)

// cveIDPattern CVE 编号格式。
//
// 宽松匹配 `CVE-YYYY-NNNN+`：序号位数从 4 位起（早期 CVE 是 4 位，
// 现在已到 7 位）。刻意不做更严的校验——CVE 编号的分配规则由 MITRE 管，
// 我们多加一条规则只会在未来挡住合法编号。
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// credentialEnvPattern 凭据环境变量名格式。
//
// 与 credentialEnvAllowed 是同一约束的两种表达（一个给正则引擎、一个给
// 前缀判断），两者必须同步。测试里有对两者的对照。
var credentialEnvPattern = regexp.MustCompile(`^` + credentialEnvPrefix + `[A-Z0-9_]{1,48}$`)

// IntegrationTypeOption 可选的情报源类型。
//
// 由后端下发而不是让前端硬编码：新增一个适配器时，前端下拉框
// 自动多出一项；若硬编码在前端，新增类型后界面里根本没有它可选，
// 而用户需要到文档里才能知道「原来支持了」。
type IntegrationTypeOption struct {
	Type string `json:"type"`
	// Label 中文名。类型的中文说法只有后端知道（它与适配器实现绑在一起），
	// 放前端会在后端新增类型时显示成空白。
	Label string `json:"label"`
	// DefaultBaseURL 界面预填用；空串表示该类型不需要地址。
	DefaultBaseURL string `json:"default_base_url"`
	// CredentialRecommended 是否建议配置凭据。
	//
	// 用「建议」而不是「必需」：不配凭据也能调 NVD（只是会被严格限流），
	// 强制必填会把「先试着拉一条看看」这个最自然的探索动作挡在门外。
	// 前端据此显示一个提示性徽标。
	CredentialRecommended bool `json:"credential_recommended"`
}

// IntegrationView 集成的对外视图。
//
// ⚠️ 这里**没有**、也永远不会有凭据的值。表里存的是环境变量名，
// 视图里给的是「那个变量名」与「它当前有没有值」——后者是运维最常踩的坑
// （配了名字却忘了设变量，表现为「一拉就报错，但配置看着都对」）。
type IntegrationView struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	// TypeLabel 类型中文名，供列表直接展示（免去前端再查一次映射表）。
	TypeLabel string `json:"type_label"`

	BaseURL string `json:"base_url"`
	// CredentialEnv 凭据所在的**环境变量名**（不是凭据）。
	CredentialEnv string `json:"credential_env"`
	// CredentialPresent 该环境变量当前在进程里是否已设置且非空。
	//
	// 只回答「有没有」，绝不回答「是什么」。这一位是为了让
	// 「配了名字但忘了设变量」在界面上可见——否则这个问题的症状是
	// 「拉取失败：401」，排查方向会被引向 API Key 本身是否有效。
	CredentialPresent bool `json:"credential_present"`

	Enabled   bool `json:"enabled"`
	TimeoutMS int  `json:"timeout_ms"`

	// —— 最近一次运行态（见迁移 000008 约束 4、5）——
	LastRunAt     *string `json:"last_run_at"`
	LastStatus    string  `json:"last_status"`
	LastError     string  `json:"last_error"`
	LastLatencyMS *int    `json:"last_latency_ms"`

	CreatedAt string `json:"created_at"`
	// UpdatedAt 行最后变更时间，**含运行态写入**（迁移 000008 约束 5）。
	// 界面不得把它当作「配置最后修改时间」。
	UpdatedAt string `json:"updated_at"`
}

// IntegrationListView 列表响应。
type IntegrationListView struct {
	Items []IntegrationView `json:"items"`
	// SupportedTypes 由后端下发，前端据此渲染类型下拉框（见 IntegrationTypeOption）。
	SupportedTypes []IntegrationTypeOption `json:"supported_types"`
	// CredentialEnvPrefix 凭据环境变量名要求的前缀，供表单做即时提示。
	// 同样由后端下发：前端硬编码这个前缀，改了后端就会出现「界面说可以、
	// 提交被拒」的分叉。
	CredentialEnvPrefix string `json:"credential_env_prefix"`
}

// VulnIntelView 一条情报快照的对外视图。
type VulnIntelView struct {
	ID     uint64 `json:"id"`
	Source string `json:"source"`
	// SourceLabel 情报源中文名。
	SourceLabel string `json:"source_label"`
	CVEID       string `json:"cve_id"`
	// Title 上游标题。NVD 不提供标题，因此可能为空——
	// 展示层用 DisplayTitle 而不是这个字段。
	Title string `json:"title"`
	// DisplayTitle title 为空时的回退展示值（退回 CVE 编号）。
	//
	// 回退放在后端而不是前端：否则每个展示点都要记得写一次 `|| cveId`，
	// 而漏掉的那一处会渲染成一片空白。
	DisplayTitle string   `json:"display_title"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	CVSSScore    *float64 `json:"cvss_score"`
	CVSSVector   string   `json:"cvss_vector"`
	PublishedAt  *string  `json:"published_at"`
	References   []string `json:"references"`
	FetchedAt    string   `json:"fetched_at"`
}

// FetchFailure 单条 CVE 的拉取失败原因。
type FetchFailure struct {
	CVEID   string `json:"cve_id"`
	Message string `json:"message"`
}

// FetchIntelResult 一次拉取的结果。
//
// ⚠️ 它恒定挂在 HTTP 200 上，**包括全部失败的情况**。
//
// 调用方必须读 Succeeded / Failed，不能只看状态码。理由见 errcode.go
// 里 P7 那一节：拉取天生是「部分成功」的，而成功的那些已经写进库了。
// 只回一个 502 会让调用方以为什么都没发生，从而重复点击。
type FetchIntelResult struct {
	IntegrationID   uint64 `json:"integration_id"`
	IntegrationName string `json:"integration_name"`
	IntegrationType string `json:"integration_type"`
	VulnID          uint64 `json:"vuln_id"`

	// Requested 本次尝试的 CVE 列表（归一化后的大写形式）。
	Requested []string `json:"requested"`
	// Succeeded / Failed 成功与失败的条数，两者之和等于 len(Requested)。
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	// Inserted / Updated 落库时新增与更新的条数（两者之和 = Succeeded）。
	Inserted int `json:"inserted"`
	Updated  int `json:"updated"`

	Items  []VulnIntelView `json:"items"`
	Errors []FetchFailure  `json:"errors"`

	// LatencyMS 本次拉取总耗时（含落库与写运行态）。
	LatencyMS int `json:"latency_ms"`
}

// CreateIntegrationInput 新建集成的入参。
type CreateIntegrationInput struct {
	Name          string
	Type          string
	BaseURL       string
	CredentialEnv string
	// Enabled / TimeoutMS 为 nil 时取默认值（启用 / 10 秒）。
	Enabled   *bool
	TimeoutMS *int
}

// UpdateIntegrationInput 修改集成的入参。
//
// CredentialEnv 用 optional.Value 表达三态（不传 / 置 null 清空 / 改）：
// 「不再使用凭据」是一个真实且常见的操作，用 *string 时它与「不修改」
// 在 Go 里都是 nil，于是这个操作怎么点都不生效而接口看起来一切正常。
type UpdateIntegrationInput struct {
	Name          *string
	Type          *string
	BaseURL       *string
	CredentialEnv optional.Value[string]
	Enabled       *bool
	TimeoutMS     *int
}

// FetchIntelInput 触发拉取的入参。
type FetchIntelInput struct {
	// VulnID 目标漏洞，必填。
	//
	// 情报接在**漏洞**层而不是整改单层（迁移 000008 约束 1）：
	// 情报描述的是漏洞本身，与「哪台机器上有它」无关。
	VulnID uint64
	// CVEID 可选。留空表示拉取该漏洞挂的全部 CVE（受上限约束）。
	CVEID string
}

// IntegrationService 三方情报源服务。
type IntegrationService struct {
	repo   *repository.Repository
	audit  *auditor
	logger *slog.Logger
	// lookupEnv 环境变量读取函数，默认为 os.LookupEnv。
	//
	// 留一个注入点是为了让「凭据未设置」这条路径可被测试覆盖：
	// 守门脚本要在不污染整个服务进程环境的前提下验证「配了变量名
	// 但环境里没有」会返回 409。直接调 os.LookupEnv 就只能靠
	// 修改进程环境来构造，那会影响并行的其他用例。
	lookupEnv func(string) (string, bool)
}

// NewIntegrationService 构建情报源服务。
func NewIntegrationService(repo *repository.Repository, logger *slog.Logger) *IntegrationService {
	if logger == nil {
		logger = slog.Default()
	}
	return &IntegrationService{
		repo:      repo,
		audit:     newAuditor(repo, logger),
		logger:    logger,
		lookupEnv: os.LookupEnv,
	}
}

// ---------------------------------------------------------------- 配置读写

// List 查询集成列表。
func (s *IntegrationService) List(ctx context.Context) (*IntegrationListView, error) {
	rows, err := s.repo.Integration.List(ctx, repository.IntegrationListQuery{})
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询集成列表失败", err)
	}

	items := make([]IntegrationView, 0, len(rows))
	for i := range rows {
		items = append(items, s.toIntegrationView(&rows[i]))
	}

	options := make([]IntegrationTypeOption, 0, len(intelfeed.Supported()))
	for _, t := range intelfeed.Supported() {
		options = append(options, IntegrationTypeOption{
			Type:                  t,
			Label:                 integrationTypeLabel(t),
			DefaultBaseURL:        intelfeed.DefaultBaseURL(t),
			CredentialRecommended: intelfeed.RequiresCredential(t),
		})
	}

	return &IntegrationListView{
		Items:               items,
		SupportedTypes:      options,
		CredentialEnvPrefix: credentialEnvPrefix,
	}, nil
}

// Get 查询单个集成。
func (s *IntegrationService) Get(ctx context.Context, id uint64) (*IntegrationView, error) {
	m, err := s.repo.Integration.FindByID(ctx, id)
	if err != nil {
		return nil, s.translateRepoError(err, "查询集成失败")
	}
	view := s.toIntegrationView(m)
	return &view, nil
}

// Create 新建集成。
func (s *IntegrationService) Create(
	ctx context.Context, p *auth.Principal, meta RequestMeta, in CreateIntegrationInput,
) (*IntegrationView, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "集成名称不能为空")
	}
	if runeLen(name) > integrationNameMaxRunes {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("集成名称不得超过 %d 个字符", integrationNameMaxRunes))
	}

	typ := strings.TrimSpace(in.Type)
	if !intelfeed.IsSupportedType(typ) {
		return nil, errIntegrationTypeUnknown(typ)
	}

	baseURL, credentialEnv, err := s.normalizeEndpointAndCredential(ctx, typ, in.BaseURL, in.CredentialEnv)
	if err != nil {
		return nil, err
	}

	// 重名先查一次，给出 409 与人话。唯一索引在并发下兜底——那时的
	// 表现是 500 而不是 409，代价可接受（不会产生重名数据）。
	if _, err := s.repo.Integration.FindByName(ctx, name); err == nil {
		return nil, errIntegrationNameTaken(name)
	} else if !errors.Is(err, repository.ErrIntegrationNotFound) {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "检查集成名称失败", err)
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	m := &model.Integration{
		Name:          name,
		Type:          typ,
		BaseURL:       baseURL,
		CredentialEnv: credentialEnv,
		Enabled:       enabled,
		TimeoutMS:     clampTimeoutMS(in.TimeoutMS),
		CreatedBy:     principalID(p),
	}
	if err := s.repo.Integration.Create(ctx, m); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "创建集成失败", err)
	}

	s.audit.record(ctx, auditEntryFor(p, meta,
		model.ActionIntegrationUpdate, "integration", fmt.Sprint(m.ID),
		integrationAuditDetail(name, typ, baseURL, credentialEnv, enabled)))

	view := s.toIntegrationView(m)
	return &view, nil
}

// Update 修改集成配置。
//
// `system:write` 把守（见 router）而不是 integration:write：
// 改 base_url 决定的是「这台服务器接下来会向哪里发起请求」，
// 那是系统设置，不是业务动作。
func (s *IntegrationService) Update(
	ctx context.Context, p *auth.Principal, meta RequestMeta, id uint64, in UpdateIntegrationInput,
) (*IntegrationView, error) {
	current, err := s.repo.Integration.FindByID(ctx, id)
	if err != nil {
		return nil, s.translateRepoError(err, "查询集成失败")
	}

	// 先算出**合并后的最终值**再整体校验，而不是逐字段校验后写库。
	// 反过来的话，「把类型从 local 改成 nvd」这种改动会绕过地址校验：
	// 单独看 base_url（空串，对 local 合法）与单独看 type（合法）都没问题，
	// 合起来却是一个「nvd 类型 + 空地址」的非法组合。
	name := current.Name
	typ := current.Type
	baseURL := current.BaseURL
	credentialEnv := current.CredentialEnv
	enabled := current.Enabled
	timeoutMS := current.TimeoutMS

	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "集成名称不能为空")
		}
		if runeLen(name) > integrationNameMaxRunes {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				fmt.Sprintf("集成名称不得超过 %d 个字符", integrationNameMaxRunes))
		}
	}
	if in.Type != nil {
		typ = strings.TrimSpace(*in.Type)
		if !intelfeed.IsSupportedType(typ) {
			return nil, errIntegrationTypeUnknown(typ)
		}
	}
	if in.BaseURL != nil {
		baseURL = strings.TrimSpace(*in.BaseURL)
	}
	if in.CredentialEnv.Present {
		credentialEnv = strings.TrimSpace(in.CredentialEnv.OrElse(""))
	}
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if in.TimeoutMS != nil {
		timeoutMS = clampTimeoutMS(in.TimeoutMS)
	}

	baseURL, credentialEnv, err = s.normalizeEndpointAndCredential(ctx, typ, baseURL, credentialEnv)
	if err != nil {
		return nil, err
	}

	// 只把**真正被请求改动**的列写进 map，而不是整行覆盖：
	// 整行覆盖会把并发场景下另一个请求刚改好的字段顶回去，
	// 而且会在审计里记下一堆「改了但值没变」的字段。
	cols := map[string]any{}
	changes := map[string]any{}
	if name != current.Name {
		cols["name"] = name
		changes["name"] = name
	}
	if typ != current.Type {
		cols["type"] = typ
		changes["type"] = typ
	}
	if baseURL != current.BaseURL {
		cols["base_url"] = baseURL
		changes["base_url"] = baseURL
	}
	if credentialEnv != current.CredentialEnv {
		cols["credential_env"] = credentialEnv
		// ⚠️ 记的是**变量名**，不是凭据（表里也从来没有凭据）。
		changes["credential_env"] = credentialEnv
	}
	if enabled != current.Enabled {
		cols["enabled"] = enabled
		changes["enabled"] = enabled
	}
	if timeoutMS != current.TimeoutMS {
		cols["timeout_ms"] = timeoutMS
		changes["timeout_ms"] = timeoutMS
	}

	if len(cols) == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "没有需要更新的配置项")
	}

	// 改名时的重名检查
	if _, changed := cols["name"]; changed {
		if other, err := s.repo.Integration.FindByName(ctx, name); err == nil && other.ID != id {
			return nil, errIntegrationNameTaken(name)
		} else if err != nil && !errors.Is(err, repository.ErrIntegrationNotFound) {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "检查集成名称失败", err)
		}
	}

	if err := s.repo.Integration.UpdateConfig(ctx, id, cols); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "更新集成配置失败", err)
	}

	changes["fields"] = sortedKeys(changes)
	s.audit.record(ctx, auditEntryFor(p, meta,
		model.ActionIntegrationUpdate, "integration", fmt.Sprint(id), changes))

	return s.Get(ctx, id)
}

// ---------------------------------------------------------------- 情报拉取

// FetchIntel 对一个漏洞触发一次情报拉取（P7 的验收标志所在）。
//
// 编排顺序是有讲究的：**先校验、再取凭据、最后才发请求**。
// 反过来的话，「地址非法」这类配置问题会表现为一次真实的外网请求
// ——那正是 SSRF 防护要避免的事。
func (s *IntegrationService) FetchIntel(
	ctx context.Context, p *auth.Principal, meta RequestMeta, id uint64, in FetchIntelInput,
) (*FetchIntelResult, error) {
	started := time.Now()

	integ, err := s.repo.Integration.FindByID(ctx, id)
	if err != nil {
		return nil, s.translateRepoError(err, "查询集成失败")
	}
	if !integ.Enabled {
		return nil, errIntegrationDisabled(integ.Name)
	}

	feed, err := intelfeed.New(integ.Type)
	if err != nil {
		// 库里的类型不受支持，说明适配器被移除而配置没清。
		// 报 400 而不是 500：用户的下一步是改类型或停用，不是「稍后重试」。
		return nil, errIntegrationTypeUnknown(integ.Type)
	}

	vuln, err := s.repo.Vuln.FindByID(ctx, in.VulnID)
	if err != nil {
		if errors.Is(err, repository.ErrVulnerabilityNotFound) {
			return nil, newError(http.StatusNotFound, errcode.CodeVulnNotFound, "漏洞不存在")
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "查询漏洞失败", err)
	}

	targets, err := resolveTargetCVEs(vuln.CVEIDs, in.CVEID)
	if err != nil {
		return nil, err
	}

	credential, err := s.resolveCredential(integ)
	if err != nil {
		return nil, err
	}

	timeout := intelfeed.ClampTimeout(time.Duration(integ.TimeoutMS) * time.Millisecond)

	records := make([]model.VulnIntel, 0, len(targets))
	failures := make([]FetchFailure, 0)
	now := time.Now()

	for _, cve := range targets {
		rec, err := feed.Fetch(ctx, intelfeed.Request{
			BaseURL:    integ.BaseURL,
			Credential: credential,
			CVEID:      cve,
			Timeout:    timeout,
		})
		if err != nil {
			// 单条失败不中断整批：另外几条可能还能成。
			// 但地址被拒是个例外——它说明**整个集成的目标**有问题，
			// 剩下的请求只会得到同一个答案，因此直接中止并回 400。
			if errors.Is(err, intelfeed.ErrEndpointBlocked) {
				reason := blockedReason(err)
				s.recordFetchAudit(ctx, p, meta, integ, in.VulnID, targets,
					len(records), len(failures)+1, time.Since(started))
				return nil, errIntegrationEndpointBlocked(reason)
			}
			failures = append(failures, FetchFailure{
				CVEID:   cve,
				Message: s.sanitizeFailureMessage(err, credential),
			})
			continue
		}
		records = append(records, toModelIntel(vuln.ID, integ.Type, rec, now))
	}

	upsertRes := repository.IntelUpsertResult{}
	if len(records) > 0 {
		upsertRes, err = s.repo.Integration.UpsertIntel(ctx, records)
		if err != nil {
			return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "写入情报快照失败", err)
		}
	}

	latency := int(time.Since(started).Milliseconds())

	// —— 写回运行态 ——
	// 判据是「本次是否**全部**成功」：部分失败也记为 failed，
	// 因为界面上那一列要回答的是「这个集成现在能不能正常用」。
	status := model.IntegrationRunSuccess
	lastErr := ""
	if len(failures) > 0 {
		status = model.IntegrationRunFailed
		lastErr = fmt.Sprintf("%d/%d 条失败：%s",
			len(failures), len(targets), failures[0].Message)
	}
	if err := s.repo.Integration.UpdateRunState(ctx, id, now, status,
		truncate(lastErr, integrationLastErrorMaxRunes), latency); err != nil {
		// 运行态写失败不影响本次拉取的结果：数据已经落库了，
		// 把它改判为失败会让用户以为白拉了并重复点击。
		s.logger.Error("写回集成运行态失败", "integration_id", id, "err", err)
	}

	s.recordFetchAudit(ctx, p, meta, integ, in.VulnID, targets, len(records), len(failures), time.Since(started))

	// 重新读一遍落库结果：这样响应里的 items 与库里的**完全一致**
	// （含 id 与 fetched_at），前端拿到就能直接渲染，不必再拉一次。
	saved, err := s.repo.Integration.ListIntelByVuln(ctx, vuln.ID)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取情报快照失败", err)
	}
	savedViews := make([]VulnIntelView, 0, len(saved))
	for i := range saved {
		savedViews = append(savedViews, toVulnIntelView(&saved[i]))
	}

	// Items 只给本次拉到的那些（按 CVE 过滤），而不是该漏洞的全部快照：
	// 调用方要判断的是「这一次拿到了什么」，全部快照会让它分不清
	// 哪些是本次新增的、哪些是上次留下的。
	thisRun := make([]VulnIntelView, 0, len(records))
	wanted := make(map[string]struct{}, len(records))
	for _, r := range records {
		wanted[r.CVEID] = struct{}{}
	}
	for _, v := range savedViews {
		if _, ok := wanted[v.CVEID]; ok {
			thisRun = append(thisRun, v)
		}
	}

	return &FetchIntelResult{
		IntegrationID:   integ.ID,
		IntegrationName: integ.Name,
		IntegrationType: integ.Type,
		VulnID:          vuln.ID,
		Requested:       targets,
		Succeeded:       len(records),
		Failed:          len(failures),
		Inserted:        upsertRes.Inserted,
		Updated:         upsertRes.Updated,
		Items:           thisRun,
		Errors:          failures,
		LatencyMS:       latency,
	}, nil
}

// ListIntelByVuln 读取某漏洞的情报快照（供漏洞详情接口内嵌）。
func (s *IntegrationService) ListIntelByVuln(ctx context.Context, vulnID uint64) ([]VulnIntelView, error) {
	rows, err := s.repo.Integration.ListIntelByVuln(ctx, vulnID)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal, "读取漏洞情报失败", err)
	}
	out := make([]VulnIntelView, 0, len(rows))
	for i := range rows {
		out = append(out, toVulnIntelView(&rows[i]))
	}
	return out, nil
}

// ---------------------------------------------------------------- 内部辅助

// normalizeEndpointAndCredential 校验并归一化「出站目标 + 凭据变量名」。
//
// 这两者一起校验而不是各管各的：它们共同决定「这次拉取会带着什么凭据
// 去访问哪里」，是同一个安全边界的两半。
func (s *IntegrationService) normalizeEndpointAndCredential(
	ctx context.Context, typ, baseURL, credentialEnv string,
) (string, string, error) {
	if runeLen(baseURL) > integrationBaseURLMaxRunes {
		return "", "", newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("上游地址不得超过 %d 个字符", integrationBaseURLMaxRunes))
	}
	if runeLen(credentialEnv) > integrationCredentialEnvMaxRunes {
		return "", "", newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("凭据环境变量名不得超过 %d 个字符", integrationCredentialEnvMaxRunes))
	}

	if credentialEnv != "" && !credentialEnvAllowed(credentialEnv) {
		return "", "", errIntegrationCredentialInvalid(credentialEnv)
	}

	// 地址校验是**第一层** SSRF 防护（第二层在 intelfeed 的连接阶段）。
	// 在保存时就校验，是为了让用户当场知道「这个地址不允许」，
	// 而不是等到某天点拉取时才收到一个 400。
	normalized, err := intelfeed.CheckEndpoint(ctx, baseURL)
	if err != nil {
		reason := blockedReason(err)
		return "", "", errIntegrationEndpointBlocked(reason)
	}

	return normalized, credentialEnv, nil
}

// resolveCredential 从环境变量取出凭据明文。
//
// ⚠️ 返回值的生命周期仅限本次请求：它被交给适配器放进请求头，
// 之后立即失去引用。它**不得**被写进日志、审计明细、错误信息或任何响应体。
func (s *IntegrationService) resolveCredential(integ *model.Integration) (string, error) {
	env := strings.TrimSpace(integ.CredentialEnv)
	if env == "" {
		// 无凭据不是错误：NVD 允许匿名调用（只是限流严格），
		// local 驱动则完全不需要凭据。
		return "", nil
	}
	value, ok := s.lookupEnv(env)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", errIntegrationCredentialMissing(env)
	}
	return value, nil
}

// sanitizeFailureMessage 把适配器错误转成可下发的中文原因。
//
// ⚠️ 这里有一道**兜底**：把凭据明文从消息里剔掉。
// 适配器本身已经保证不带凭据（见 nvd.go 的注释），但那是一条
// 「靠每个实现自觉遵守」的约定；而这类约定的失效方式是静默的
// ——某个新适配器在错误信息里拼一次 URL，凭据就进了审计与响应。
// 因此在出口处再加一道，与 sanitize.JSON 对请求体的处理是同一个思路。
func (s *IntegrationService) sanitizeFailureMessage(err error, credential string) string {
	switch {
	case errors.Is(err, intelfeed.ErrNotFound):
		return "上游未收录该 CVE 编号（请确认编号是否正确）"
	case errors.Is(err, intelfeed.ErrEndpointBlocked):
		reason := blockedReason(err)
		return "出站目标被安全策略拒绝：" + reason
	}

	msg := err.Error()
	if credential != "" {
		msg = strings.ReplaceAll(msg, credential, "***")
	}
	return truncate(msg, integrationLastErrorMaxRunes)
}

// recordFetchAudit 写一条拉取审计。
//
// 失败路径也要写：审计要回答的是「谁让服务器去连过哪个地址」，
// 而失败的尝试恰恰是最需要留痕的那种。
func (s *IntegrationService) recordFetchAudit(
	ctx context.Context, p *auth.Principal, meta RequestMeta,
	integ *model.Integration, vulnID uint64, targets []string,
	succeeded, failed int, elapsed time.Duration,
) {
	detail := map[string]any{
		"integration_id":   integ.ID,
		"integration_name": integ.Name,
		"integration_type": integ.Type,
		// base_url 要记：它回答了「服务器实际去向哪里发起了请求」。
		"base_url":   integ.BaseURL,
		"vuln_id":    vulnID,
		"cve_ids":    targets,
		"succeeded":  succeeded,
		"failed":     failed,
		"latency_ms": elapsed.Milliseconds(),
	}
	// 只记变量**名**，绝不记它的值。sanitize.JSON 还有一道敏感字段剔除，
	// 但那一道按字段名匹配（password / token …），而这里连字段都不出现。
	if integ.CredentialEnv != "" {
		detail["credential_env"] = integ.CredentialEnv
	}
	s.audit.record(ctx, auditEntryFor(p, meta,
		model.ActionIntegrationFetch, "integration", fmt.Sprint(integ.ID), detail))
}

// toIntegrationView 组装集成视图。
func (s *IntegrationService) toIntegrationView(m *model.Integration) IntegrationView {
	view := IntegrationView{
		ID:            m.ID,
		Name:          m.Name,
		Type:          m.Type,
		TypeLabel:     integrationTypeLabel(m.Type),
		BaseURL:       m.BaseURL,
		CredentialEnv: m.CredentialEnv,
		Enabled:       m.Enabled,
		TimeoutMS:     m.TimeoutMS,
		LastStatus:    m.LastStatus,
		LastError:     m.LastError,
		LastLatencyMS: m.LastLatencyMS,
		CreatedAt:     m.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     m.UpdatedAt.Format(time.RFC3339),
	}
	// credential_present 只回答「有没有」，绝不回答「是什么」。
	if m.CredentialEnv != "" {
		if v, ok := s.lookupEnv(m.CredentialEnv); ok && strings.TrimSpace(v) != "" {
			view.CredentialPresent = true
		}
	}
	if m.LastRunAt != nil {
		t := m.LastRunAt.Format(time.RFC3339)
		view.LastRunAt = &t
	}
	return view
}

// translateRepoError 把仓储错误翻译成业务错误。
func (s *IntegrationService) translateRepoError(err error, action string) error {
	if errors.Is(err, repository.ErrIntegrationNotFound) {
		return errIntegrationNotFound()
	}
	return wrapError(http.StatusInternalServerError, errcode.CodeInternal, action, err)
}

// toVulnIntelView 组装情报视图。
func toVulnIntelView(m *model.VulnIntel) VulnIntelView {
	view := VulnIntelView{
		ID:          m.ID,
		Source:      m.Source,
		SourceLabel: integrationTypeLabel(m.Source),
		CVEID:       m.CVEID,
		Title:       m.Title,
		Severity:    m.Severity,
		CVSSScore:   m.CVSSScore,
		CVSSVector:  m.CVSSVector,
		FetchedAt:   m.FetchedAt.Format(time.RFC3339),
		References:  decodeReferences(m.ReferencesJSON),
	}
	// NVD 不提供标题，因此这里的回退是常态而非例外。
	// 回退放后端：每个展示点各写一次 `|| cveId` 的话，漏掉的那处会渲染成空白。
	view.DisplayTitle = m.Title
	if strings.TrimSpace(view.DisplayTitle) == "" {
		view.DisplayTitle = m.CVEID
	}
	if m.Description != nil {
		view.Description = *m.Description
	}
	if m.PublishedAt != nil {
		t := m.PublishedAt.Format(time.RFC3339)
		view.PublishedAt = &t
	}
	return view
}

// decodeReferences 解析参考链接 JSON。
//
// 解析失败返回空切片而不是报错：这一列是**展示用**的附加信息，
// 它坏掉不该让整条情报不可读（描述与分数仍然有价值）。
func decodeReferences(raw *string) []string {
	out := []string{}
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return out
	}
	if err := json.Unmarshal([]byte(*raw), &out); err != nil {
		return []string{}
	}
	return out
}

// toModelIntel 把适配器的记录转成落库模型。
func toModelIntel(vulnID uint64, source string, rec *intelfeed.Record, at time.Time) model.VulnIntel {
	row := model.VulnIntel{
		VulnID:      vulnID,
		Source:      source,
		CVEID:       rec.CVEID,
		Title:       truncate(rec.Title, integrationTitleMaxRunes),
		Severity:    rec.Severity,
		CVSSScore:   rec.CVSSScore,
		CVSSVector:  truncate(rec.CVSSVector, 128),
		PublishedAt: rec.Published,
		FetchedAt:   at,
	}

	if desc := strings.TrimSpace(rec.Description); desc != "" {
		d := truncateRunes(desc, integrationDescMaxRunes)
		row.Description = &d
	}
	if len(rec.References) > 0 {
		if b, err := json.Marshal(rec.References); err == nil {
			s := string(b)
			row.ReferencesJSON = &s
		}
	}
	if len(rec.Raw) > 0 {
		raw := rec.Raw
		if len(raw) > integrationRawJSONMaxBytes {
			raw = raw[:integrationRawJSONMaxBytes]
		}
		s := string(raw)
		row.RawJSON = &s
	}

	return row
}

// resolveTargetCVEs 决定本次要拉取哪些 CVE。
//
// 三条规则，都有明确理由：
//
//	显式给出 cve_id → 只拉它，但**必须属于该漏洞**
//	未给出且漏洞有 CVE → 拉全部（受上限约束）
//	未给出且漏洞没有 CVE → 400（用户需要显式指定，但手工录入的漏洞
//	                       往往确实没有 CVE，所以文案要告诉他这一点）
func resolveTargetCVEs(vulnCVEIDs, requested string) ([]string, error) {
	available := splitCVEIDs(vulnCVEIDs)

	if req := strings.ToUpper(strings.TrimSpace(requested)); req != "" {
		if !cveIDPattern.MatchString(req) {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				"CVE 编号格式不正确，应形如 CVE-2021-44228")
		}
		for _, c := range available {
			if c == req {
				return []string{req}, nil
			}
		}
		// 不允许拉一条与目标漏洞无关的 CVE：情报是漏洞的属性，
		// 允许挂任意 CVE 会让「这条情报凭什么挂在这条漏洞上」无从回答。
		detail := "该漏洞的 CVE 列表里没有这条编号"
		if len(available) == 0 {
			detail = "该漏洞没有登记任何 CVE 编号"
		}
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			"不能对该漏洞拉取 "+req+"："+detail)
	}

	if len(available) == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			"该漏洞没有登记 CVE 编号，无法从情报源拉取。"+
				"如果是手工录入的漏洞，请先补上 CVE 编号；若有明确目标，也可在请求里指定 cve_id")
	}

	if len(available) > integrationMaxCVEsPerFetch {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("该漏洞挂了 %d 个 CVE，超过单次拉取上限 %d 个。"+
				"请指定要拉取的 cve_id", len(available), integrationMaxCVEsPerFetch))
	}

	return available, nil
}

// splitCVEIDs 拆分逗号分隔的 CVE 串，归一化为大写并去重。
//
// 归一化是必须的：库里存的是解析器给的原始写法，
// 而唯一键 (vuln_id, source, cve_id) 按字符串比较——
// 同一编号的大小写差异会让它变成两条记录。
func splitCVEIDs(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		v := strings.ToUpper(strings.TrimSpace(p))
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// credentialEnvAllowed 凭据环境变量名的白名单判定。
//
// ▍为什么必须有这条限制
//
// 「凭据走环境变量」这个决策本身是对的（库会流出、环境变量不会）。
// 但如果把变量**名**完全交给用户填，这个设计会立刻反转成漏洞：
//
//	① 攻击者（任何有 system:write 的人）把 credential_env 改成
//	   SR_AUTH_JWT_SECRET / SR_DATABASE_PASSWORD；
//	② 把 base_url 指向自己的服务器；
//	③ 点一次「拉取」。
//
// 于是那个变量的**值**会作为请求头原样发到他手上。这不是 SSRF，
// 而是一个「读取进程内任意环境变量」的原语——破坏力更大，
// 因为它是直接的凭据窃取。
//
// 前缀限制把可读范围收窄到「专供情报源使用的几个变量」。
// 它不完美（部署时若把别的敏感值也塞进 SR_INTEL_ 前缀就失效了），
// 但把「任意变量」变成「约定前缀」，是从「无限制」到「有边界」的质变。
//
// ⚠️ 正则与这里的前缀判断必须同步：credentialEnvPattern 是同一约束的
// 另一种表达，测试里有对照断言。
func credentialEnvAllowed(name string) bool {
	if !strings.HasPrefix(name, credentialEnvPrefix) {
		return false
	}
	return credentialEnvPattern.MatchString(name)
}

// integrationTypeLabel 类型的中文名。
//
// 放后端而不是前端：它和适配器实现绑在一起（新增一个源就要加一行），
// 前端硬编码会在后端新增类型时显示成空白，而空白不会报错。
func integrationTypeLabel(t string) string {
	switch t {
	case intelfeed.TypeNVD:
		return "NVD（美国国家漏洞数据库）"
	case intelfeed.TypeLocal:
		return "本地离线驱动（不访问网络）"
	default:
		// 库里的类型可能是历史遗留（适配器已被移除），如实回显原值，
		// 让运维看得出「这是个我不认识的类型」，而不是收到一片空白。
		return t
	}
}

// integrationAuditDetail 集成配置变更的审计明细。
func integrationAuditDetail(name, typ, baseURL, credentialEnv string, enabled bool) map[string]any {
	d := map[string]any{
		"name":     name,
		"type":     typ,
		"base_url": baseURL,
		"enabled":  enabled,
	}
	if credentialEnv != "" {
		// 变量名，不是凭据本身。
		d["credential_env"] = credentialEnv
	}
	return d
}

// clampTimeoutMS 把毫秒超时收敛到 intelfeed 允许的区间。
//
// 走一趟 Duration 是为了让「允许区间」只有 intelfeed 一个出处：
// 在这里再写一份 [1000, 30000] 就等于多了一个会分叉的定义。
func clampTimeoutMS(ms *int) int {
	raw := 0
	if ms != nil {
		raw = *ms
	}
	return int(intelfeed.ClampTimeout(time.Duration(raw)*time.Millisecond) / time.Millisecond)
}

// blockedReason 从被拦截的错误里取出去掉前缀的原因文本。
//
// 适配器的错误形如「intelfeed: 出站目标被安全策略拒绝：xxx」，
// 而给用户看的文案里已经有一句「上游地址不被允许：」，
// 不去掉前缀就会出现「上游地址不被允许：intelfeed: 出站目标被安全策略拒绝：xxx」。
func blockedReason(err error) string {
	msg := err.Error()
	if idx := strings.LastIndex(msg, "："); idx >= 0 && idx+len("：") < len(msg) {
		return strings.TrimSpace(msg[idx+len("："):])
	}
	return msg
}

// runeLen 按字符数（而非字节数）计长度。
//
// 列宽是按字符算的（utf8mb4 的 VARCHAR(64) 是 64 个字符），
// 用 len() 会让一个 30 字的中文名称（90 字节）被误判为超长。
func runeLen(s string) int {
	return len([]rune(s))
}

// truncateRunes 按字符数截断。
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}
