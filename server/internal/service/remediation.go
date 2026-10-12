package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/pkg/optional"
	"secrisk/server/internal/repository"
)

// 整改单字段长度上限，与迁移 000007 的列宽一一对应。
//
// 在服务层拦一道而不是让 MySQL 去截断/报错：MySQL 非严格模式下
// 会**静默截断**超长的说明文字，用户写了一段整改结论、保存后少了后半段，
// 而且没有任何提示。
const (
	remediationTitleMaxRunes  = 255
	remediationDescMaxRunes   = 1000
	remediationResoluMaxRunes = 1000
	remediationNoteMaxRunes   = 500
)

const (
	// remediationBatchMax 单次批量建单上限。
	//
	// 500 这个数的取值理由：按「很高 + 高」批量建单，一次几百张已经是
	// 一个正常评估的量级；再大就说明用户漏选了等级筛选，此时正确做法是
	// 报错让他收窄条件，而不是替他建出几千张单子——那些单子既没人会看，
	// 又会把「逾期数」这个指标彻底废掉。
	remediationBatchMax = 500

	// remediationDueSoonDays 仪表盘「即将到期」的窗口天数（含今天）。
	remediationDueSoonDays = 7

	// remediationRecentLimit 仪表盘「最近动态」条数。
	remediationRecentLimit = 5
)

// RemediationView 整改单的对外视图。
//
// ▍为什么时间态是三个字段而不是一个
//
// 「还有几天到期」与「已逾期几天」在语义上是**互斥**的两件事：
// 未逾期时看前者，逾期时看后者。合成一个有符号的字段（负号表示逾期）
// 能少一个字段，代价是每个消费方都要记得那个符号约定——
// 一旦忘了，界面上就会出现「逾期 -3 天」。宁可多一个字段，
// 也不要把约定藏在符号里。
//
//	未设期限     overdue=false, overdue_days=0, due_in_days=null
//	未逾期       overdue=false, overdue_days=0, due_in_days>=0（0 = 今天到期）
//	已逾期未闭环 overdue=true,  overdue_days>0,  due_in_days=null
//	已闭环       overdue=false, overdue_days=0, due_in_days=null
//
// ⚠️ 最后一行是有意的：**逾期是当前态，不是一个历史事实**。
// 一张逾期三天才闭环的单子，闭环之后就不再是「逾期」的了。
// 「历史逾期率」需要落库才能算，本期不做（见 docs/13 非目标）。
type RemediationView struct {
	ID uint64 `json:"id"`

	// —— 业务身份 ——
	AssetID uint64 `json:"asset_id"`
	VulnID  uint64 `json:"vuln_id"`
	// AssessmentID / RiskItemID 是**发现出处**，可能失效（见迁移 000007 约束 1）。
	// RiskItemID 在源评估被重算之后即指向不存在的行——这是设计允许的，
	// 前端跳转时若 404 就只提示「来源评估已更新」，不影响单子本身。
	AssessmentID *uint64 `json:"assessment_id"`
	RiskItemID   *uint64 `json:"risk_item_id"`

	// —— 快照 ——
	AssetName  string  `json:"asset_name"`
	AssetIP    string  `json:"asset_ip"`
	VulnTitle  string  `json:"vuln_title"`
	VulnCVEIDs string  `json:"vuln_cve_ids"`
	RiskLevel  string  `json:"risk_level"`
	RiskValueR float64 `json:"risk_value_r"`

	// —— 单子内容 ——
	Title       string `json:"title"`
	Description string `json:"description"`
	Resolution  string `json:"resolution"`

	Status       string  `json:"status"`
	AssigneeID   *uint64 `json:"assignee_id"`
	AssigneeName string  `json:"assignee_name"`
	DueDate      *string `json:"due_date"`

	// —— 时间态（算出来的，见 D4）——
	Overdue     bool `json:"overdue"`
	OverdueDays int  `json:"overdue_days"`
	DueInDays   *int `json:"due_in_days"`

	// Transitions 当前状态可选的下一步。
	//
	// ⚠️ 这是**后端的状态机投影**，不是前端另写一份规则。
	// 前端渲染操作按钮时直接遍历它，因此「界面允许但接口拒绝」这类
	// 不一致在结构上就不可能出现。NoteRequired 同理——它是后端
	// 校验规则的投影，前端据此决定要不要把说明框标成必填。
	Transitions []RemediationTransitionOption `json:"transitions"`

	CreatedByName string  `json:"created_by_name"`
	ClosedAt      *string `json:"closed_at"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// RemediationTransitionOption 一次可选的流转。
type RemediationTransitionOption struct {
	ToStatus string `json:"to_status"`
	// NoteRequired 本次流转是否必须填写说明（后端强制校验，前端据此标必填）。
	NoteRequired bool `json:"note_required"`
}

// RemediationLogView 一条流转 / 变更记录。
type RemediationLogView struct {
	ID         uint64  `json:"id"`
	Action     string  `json:"action"`
	FromStatus string  `json:"from_status"`
	ToStatus   string  `json:"to_status"`
	Note       string  `json:"note"`
	OperatorID *uint64 `json:"operator_id"`
	// OperatorName 是当时的快照（不是实时查用户表）：
	// 时间线要回答的是「当时是谁做的」，账号后来改名不该改写历史。
	OperatorName string `json:"operator_name"`
	CreatedAt    string `json:"created_at"`
}

// RemediationDetailView 整改单详情：单子 + 完整时间线。
type RemediationDetailView struct {
	Remediation RemediationView      `json:"remediation"`
	Logs        []RemediationLogView `json:"logs"`
}

// CreateRemediationInput 建单入参。
//
// RiskItemID 必填：整改单必须有风险等级与风险值，而这两者只有风险项
// 才有（见 docs/13 §4.1）。直接给 asset_id + vuln_id 建单看似更灵活，
// 但那会造出「等级为空」的单子，而仪表盘的「按等级统计整改」与
// 「按等级排逾期清单」都依赖它 —— 一个可以合法为空的字段，
// 迟早会变成一堆没人能解释的空格子。
type CreateRemediationInput struct {
	RiskItemID  uint64
	Title       string
	Description string
	AssigneeID  *uint64
	// DueDate 形如 2026-11-01；空串表示不设期限。
	DueDate string
}

// UpdateRemediationInput 改字段入参。
//
// 不含 Status：状态流转走 Transition，两者是不同的动作
// （与 asset-groups 的 move 独立于 PATCH 同理）。混在一起的话，
// 「改期限」与「打回」会变成同一个接口，审计里只能看到一个 update。
type UpdateRemediationInput struct {
	Title       *string
	Description *string
	Resolution  *string
	// AssigneeID 三态：不传=不动，null=取消分派，值=改为该人。
	AssigneeID optional.Value[uint64]
	// DueDate 三态：不传=不动，null=清除期限，值=改为该日期。
	DueDate optional.Value[string]
}

// TransitionRemediationInput 状态流转入参。
type TransitionRemediationInput struct {
	ToStatus string
	Note     string
}

// ListRemediationQuery 列表查询入参。
type ListRemediationQuery struct {
	Keyword    string
	Status     *string
	ActiveOnly bool
	AssigneeID *uint64
	Level      *string
	// AssessmentID 按发现出处过滤。
	AssessmentID *uint64
	Overdue      bool
	Page         int
	PageSize     int
}

// BatchCreateRemediationInput 批量建单入参。
type BatchCreateRemediationInput struct {
	AssessmentID uint64
	// Levels 只对哪些等级的风险项建单；为空时取「很高 + 高」。
	Levels     []string
	DueInDays  *int
	AssigneeID *uint64
}

// BatchCreateRemediationResult 批量建单结果。
type BatchCreateRemediationResult struct {
	AssessmentID uint64 `json:"assessment_id"`
	Matched      int    `json:"matched"`
	Created      int    `json:"created"`
	// Skipped 已有未闭环单、因而跳过的条数（幂等的直接体现）。
	Skipped int `json:"skipped"`
	// Ids 本次新建的整改单 ID。
	Ids []uint64 `json:"ids"`
}

// RemediationService 整改跟踪服务。
type RemediationService struct {
	repo   *repository.Repository
	audit  *auditor
	logger *slog.Logger
	// now 注入时间源，便于测试构造「逾期 / 未逾期」的边界。
	// 生产传 nil 时退化为 time.Now。
	now func() time.Time
}

// NewRemediationService 构建整改跟踪服务。
func NewRemediationService(repo *repository.Repository, logger *slog.Logger) *RemediationService {
	if logger == nil {
		logger = slog.Default()
	}
	return &RemediationService{
		repo:   repo,
		audit:  newAuditor(repo, logger),
		logger: logger,
		now:    time.Now,
	}
}

// today 返回「今天」的零点，是全部逾期判定的唯一时间基准。
func (s *RemediationService) today() time.Time {
	n := s.now()
	return time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, n.Location())
}

// ------------------------------------------------------------------ 查询

// List 分页查询整改单。
func (s *RemediationService) List(
	ctx context.Context, q ListRemediationQuery,
) ([]RemediationView, int64, error) {
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 20
	}
	if q.Status != nil && !model.RemediationStatus(*q.Status).Valid() {
		return nil, 0, errRemediationStatusInvalid(*q.Status)
	}

	var statuses []string
	if q.ActiveOnly {
		statuses = remediationStatusStrings(model.RemediationActiveStatuses)
	}

	rows, total, err := s.repo.Remediation.List(ctx, repository.RemediationListQuery{
		Keyword:      q.Keyword,
		Status:       q.Status,
		Statuses:     statuses,
		AssigneeID:   q.AssigneeID,
		Level:        q.Level,
		AssessmentID: q.AssessmentID,
		Overdue:      q.Overdue,
		Today:        s.today(),
		Page:         q.Page,
		PageSize:     q.PageSize,
	})
	if err != nil {
		return nil, 0, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询整改单列表失败", err)
	}

	names, err := s.resolveNames(ctx, rows)
	if err != nil {
		return nil, 0, err
	}
	today := s.today()
	views := make([]RemediationView, 0, len(rows))
	for i := range rows {
		views = append(views, toRemediationView(&rows[i], today, names))
	}
	return views, total, nil
}

// Get 查询整改单详情（含流转时间线）。
func (s *RemediationService) Get(
	ctx context.Context, id uint64,
) (*RemediationDetailView, error) {
	m, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	logs, err := s.repo.Remediation.ListLogs(ctx, id)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询整改单记录失败", err)
	}

	views := make([]RemediationLogView, 0, len(logs))
	for i := range logs {
		l := &logs[i]
		views = append(views, RemediationLogView{
			ID:           l.ID,
			Action:       l.Action,
			FromStatus:   l.FromStatus,
			ToStatus:     l.ToStatus,
			Note:         l.Note,
			OperatorID:   l.OperatorID,
			OperatorName: l.OperatorName,
			CreatedAt:    l.CreatedAt.Format(time.RFC3339),
		})
	}

	names, err := s.resolveNames(ctx, []model.Remediation{*m})
	if err != nil {
		return nil, err
	}
	return &RemediationDetailView{
		Remediation: toRemediationView(m, s.today(), names),
		Logs:        views,
	}, nil
}

// ------------------------------------------------------------------ 建单

// Create 由一条风险项建整改单。
//
// 三步都在这里：取风险项的快照 → 查是否已有未闭环单 → 事务内建单 + 写首条记录。
func (s *RemediationService) Create(
	ctx context.Context, principal *auth.Principal, meta RequestMeta, in CreateRemediationInput,
) (*RemediationView, error) {
	item, err := s.loadRiskItem(ctx, in.RiskItemID)
	if err != nil {
		return nil, err
	}

	dueDate, err := parseDueDate(in.DueDate)
	if err != nil {
		return nil, err
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = item.VulnTitle
	}
	if err := checkRemediationText("整改单标题", title, remediationTitleMaxRunes); err != nil {
		return nil, err
	}
	if err := checkRemediationText("整改说明", in.Description, remediationDescMaxRunes); err != nil {
		return nil, err
	}

	m := newRemediationFromItem(item, principal)
	m.Title = title
	m.Description = strings.TrimSpace(in.Description)
	m.AssigneeID = in.AssigneeID
	m.DueDate = dueDate

	// 先查一次给友好错误；唯一索引在并发下兜底（见迁移 000007 约束 2）。
	// 这里的检查**不是**防线，只是把「Duplicate entry '7:9'」翻译成人话。
	if err := s.ensureNoActiveTicket(ctx, m.AssetID, m.VulnID, 0); err != nil {
		return nil, err
	}

	if err := s.createWithLog(ctx, m, principal, model.RemediationLogCreate); err != nil {
		return nil, err
	}

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionRemediationCreate, "remediation", fmt.Sprintf("%d", m.ID),
		map[string]any{
			"asset_id":     m.AssetID,
			"vuln_id":      m.VulnID,
			"risk_item_id": m.RiskItemID,
			"risk_level":   m.RiskLevel,
			"title":        m.Title,
		}))

	names, err := s.resolveNames(ctx, []model.Remediation{*m})
	if err != nil {
		return nil, err
	}
	view := toRemediationView(m, s.today(), names)
	return &view, nil
}

// BatchCreate 按评估 + 等级批量建单。
//
// 幂等语义：已存在未闭环单的 (资产, 漏洞) **跳过而不报错**。
// 这一点与单张建单（重复即 409）刻意不同——批量建单的典型用法是
// 「算完一次评估后把高风险的都开单」，用户会在评估重算后再点一次；
// 若那时因为已有单子而整批失败，这个功能就没法用了。
func (s *RemediationService) BatchCreate(
	ctx context.Context, principal *auth.Principal, meta RequestMeta,
	in BatchCreateRemediationInput,
) (*BatchCreateRemediationResult, error) {
	if in.AssessmentID == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "评估任务 ID 非法")
	}

	// 评估必须存在且已计算：草稿状态没有任何风险项，按它建单只会
	// 得到一份「命中 0 条」的空结果，而用户真正需要知道的是「先算一次」。
	a, err := s.repo.Assessment.FindByID(ctx, in.AssessmentID)
	if err != nil {
		if errors.Is(err, repository.ErrAssessmentNotFound) {
			return nil, newError(http.StatusNotFound, errcode.CodeAssessmentNotFound, "评估任务不存在")
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询评估任务失败", err)
	}
	if a.Status != model.AssessmentCalculated {
		return nil, errRemediationBatchEmpty()
	}

	levels, err := normalizeLevels(in.Levels)
	if err != nil {
		return nil, err
	}

	// 先数后取：条数决定「报超限」还是「照常执行」，而超限文案里必须给出
	// 准确数字，否则用户不知道该把条件收窄到什么程度。
	matchedCount, err := s.repo.Assessment.CountRiskItemsByLevels(ctx, in.AssessmentID, levels)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"统计风险项条数失败", err)
	}
	if matchedCount == 0 {
		return nil, errRemediationBatchEmpty()
	}
	if matchedCount > remediationBatchMax {
		return nil, errRemediationBatchTooLarge(int(matchedCount), remediationBatchMax)
	}

	// 已经确认不超过上限，limit 取上限即可（不会截断）。
	items, err := s.repo.Assessment.ListRiskItemsByLevels(
		ctx, in.AssessmentID, levels, remediationBatchMax)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询风险项失败", err)
	}
	matched := make([]*model.RiskItem, 0, len(items))
	for i := range items {
		matched = append(matched, &items[i])
	}
	if len(matched) == 0 {
		// 并发下风险项可能刚被重算清空（calculate 是先清后写）。
		return nil, errRemediationBatchEmpty()
	}

	// 一次性取回「已有未闭环单」的 (资产, 漏洞)，避免逐条查询。
	assetIDs := make([]uint64, 0, len(matched))
	for _, it := range matched {
		assetIDs = append(assetIDs, it.AssetID)
	}
	existing, err := s.repo.Remediation.ActiveByTargets(ctx, assetIDs)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询已有整改单失败", err)
	}

	var dueDate *time.Time
	if in.DueInDays != nil {
		if *in.DueInDays < 0 {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				"到期天数不能为负数")
		}
		d := s.today().AddDate(0, 0, *in.DueInDays)
		dueDate = &d
	}

	created := make([]uint64, 0, len(matched))
	skipped := 0
	for _, it := range matched {
		if _, ok := existing[repository.TargetKey{AssetID: it.AssetID, VulnID: it.VulnID}]; ok {
			skipped++
			continue
		}
		m := newRemediationFromItem(it, principal)
		m.AssigneeID = in.AssigneeID
		m.DueDate = dueDate
		// 批量走与单张相同的写入路径：同一条 INSERT、同一条 create 记录。
		// 复制一份「精简版」写入逻辑会让批量建出的单子缺少首条记录，
		// 表现为详情页时间线是空的——而它只在批量这条路线上出现。
		if err := s.createWithLog(ctx, m, principal, model.RemediationLogCreate); err != nil {
			// 并发下可能被唯一索引拦下（两次批量同时跑）：跳过而不是整批失败，
			// 与上面的幂等语义一致。
			if isDuplicateKey(err) {
				skipped++
				continue
			}
			return nil, err
		}
		created = append(created, m.ID)
	}

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionRemediationBatchCreate, "remediation", fmt.Sprintf("%d", in.AssessmentID),
		map[string]any{
			"assessment_id": in.AssessmentID,
			"levels":        levels,
			"matched":       len(matched),
			"created":       len(created),
			"skipped":       skipped,
		}))

	return &BatchCreateRemediationResult{
		AssessmentID: in.AssessmentID,
		Matched:      len(matched),
		Created:      len(created),
		Skipped:      skipped,
		Ids:          created,
	}, nil
}

// ------------------------------------------------------------------ 修改

// Update 改字段（不含状态）。
func (s *RemediationService) Update(
	ctx context.Context, principal *auth.Principal, meta RequestMeta,
	id uint64, in UpdateRemediationInput,
) (*RemediationView, error) {
	m, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}

	cols := make(map[string]any)
	if in.Title != nil {
		title := strings.TrimSpace(*in.Title)
		if title == "" {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam, "整改单标题不能为空")
		}
		if err := checkRemediationText("整改单标题", title, remediationTitleMaxRunes); err != nil {
			return nil, err
		}
		cols["title"] = title
	}
	if in.Description != nil {
		if err := checkRemediationText("整改说明", *in.Description, remediationDescMaxRunes); err != nil {
			return nil, err
		}
		cols["description"] = strings.TrimSpace(*in.Description)
	}
	if in.Resolution != nil {
		if err := checkRemediationText("整改结论", *in.Resolution, remediationResoluMaxRunes); err != nil {
			return nil, err
		}
		cols["resolution"] = strings.TrimSpace(*in.Resolution)
	}
	if in.AssigneeID.Present {
		// nil = 取消分派（回到「没人负责」），与「不传」是两件事。
		// 展开成裸 nil 而不是把 *uint64 塞进 map：GORM 收到一个类型化的
		// nil 指针时并不总是写出 NULL，展开成裸 nil 才是确定的。
		if in.AssigneeID.Value == nil {
			cols["assignee_id"] = nil
		} else {
			cols["assignee_id"] = *in.AssigneeID.Value
		}
	}
	if in.DueDate.Present {
		if in.DueDate.Value == nil {
			cols["due_date"] = nil
		} else {
			d, err := parseDueDate(*in.DueDate.Value)
			if err != nil {
				return nil, err
			}
			if d == nil {
				cols["due_date"] = nil
			} else {
				cols["due_date"] = *d
			}
		}
	}

	if len(cols) == 0 {
		names, err := s.resolveNames(ctx, []model.Remediation{*m})
		if err != nil {
			return nil, err
		}
		view := toRemediationView(m, s.today(), names)
		return &view, nil
	}

	if err := s.repo.Remediation.Update(ctx, id, cols); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"更新整改单失败", err)
	}
	s.appendLog(ctx, id, principal, model.RemediationLogUpdate, "", "", changeNote(cols))

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionRemediationUpdate, "remediation", fmt.Sprintf("%d", id),
		map[string]any{"changed": sortedKeys(cols)}))

	updated, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	names, err := s.resolveNames(ctx, []model.Remediation{*updated})
	if err != nil {
		return nil, err
	}
	view := toRemediationView(updated, s.today(), names)
	return &view, nil
}

// Transition 状态流转。
//
// ▍为什么这条路径单独存在，而不是 PATCH 里的一个 status 字段
//
// 三个理由，每一个单独都够：
//  1. 它有**额外的必填参数**（说明），塞进 PATCH 就得做条件必填；
//  2. 它是**打回 / 闭环 / 风险接受**这些审计上必须能一眼筛出的动作，
//     混进 update 之后审计页再也分不清「改了个期限」与「把单子打回了」；
//  3. 它写两张表（单子 + 流转记录），而 PATCH 只写一张。
func (s *RemediationService) Transition(
	ctx context.Context, principal *auth.Principal, meta RequestMeta,
	id uint64, in TransitionRemediationInput,
) (*RemediationView, error) {
	m, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}

	to := model.RemediationStatus(strings.TrimSpace(in.ToStatus))
	if !to.Valid() {
		return nil, errRemediationStatusInvalid(in.ToStatus)
	}
	if !model.CanTransition(m.Status, to) {
		return nil, errRemediationTransitionInvalid(
			string(m.Status), string(to), nextStatusLabels(m.Status))
	}

	note := strings.TrimSpace(in.Note)
	if noteRequired(m.Status, to) && note == "" {
		return nil, errRemediationNoteRequired(string(to))
	}
	if err := checkRemediationText("流转说明", note, remediationNoteMaxRunes); err != nil {
		return nil, err
	}

	from := m.Status
	cols := map[string]any{"status": string(to)}
	if to.Terminal() {
		cols["closed_at"] = s.now()
		// 进入终态时把说明同时写入 resolution：结论不该只躺在日志里，
		// 列表页要能直接显示「怎么解决的」。
		if note != "" {
			cols["resolution"] = note
		}
	}
	if err := s.repo.Remediation.Update(ctx, id, cols); err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"更新整改单状态失败", err)
	}
	s.appendLog(ctx, id, principal, model.RemediationLogTransition,
		string(from), string(to), note)

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionRemediationTransition, "remediation", fmt.Sprintf("%d", id),
		map[string]any{
			"from": string(from),
			"to":   string(to),
			"note": truncate(note, 200),
		}))

	updated, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	names, err := s.resolveNames(ctx, []model.Remediation{*updated})
	if err != nil {
		return nil, err
	}
	view := toRemediationView(updated, s.today(), names)
	return &view, nil
}

// Delete 删除整改单。
//
// 只允许「待处理且从未流转」——已经流转过的单子是工作记录，
// 删掉它就等于抹掉「有人承诺过要修、后来又改了口」这个事实。
// 报错文案里给出替代动作（改成风险接受），而不是只说「不允许」。
func (s *RemediationService) Delete(
	ctx context.Context, principal *auth.Principal, meta RequestMeta, id uint64,
) error {
	m, err := s.find(ctx, id)
	if err != nil {
		return err
	}

	if n, err := s.repo.Remediation.CountTransitionLogs(ctx, id); err != nil {
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询整改单记录失败", err)
	} else if n > 0 {
		return errRemediationDeleteForbidden(
			"该整改单已经有过状态流转，属于工作记录，不能删除。" +
				"如果不再需要整改，请流转为「风险接受」并写明理由")
	}
	if m.Status != model.RemediationPending {
		return errRemediationDeleteForbidden(
			"只有「待处理」状态的整改单可以删除，当前状态为「" +
				string(m.Status) + "」。如果不再需要整改，请流转为「风险接受」")
	}

	if err := s.repo.Remediation.Delete(ctx, id); err != nil {
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"删除整改单失败", err)
	}

	s.audit.record(ctx, auditEntryFor(principal, meta,
		model.ActionRemediationDelete, "remediation", fmt.Sprintf("%d", id),
		map[string]any{
			"asset_id":   m.AssetID,
			"vuln_id":    m.VulnID,
			"title":      m.Title,
			"risk_level": m.RiskLevel,
		}))
	return nil
}

// ------------------------------------------------------------------ 内部

// find 取整改单，把仓储的「不存在」翻译成业务错误。
func (s *RemediationService) find(ctx context.Context, id uint64) (*model.Remediation, error) {
	m, err := s.repo.Remediation.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrRemediationNotFound) {
			return nil, errRemediationNotFound()
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询整改单失败", err)
	}
	return m, nil
}

// loadRiskItem 取风险项（建单的来源）。
func (s *RemediationService) loadRiskItem(ctx context.Context, id uint64) (*model.RiskItem, error) {
	if id == 0 {
		return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			"必须指定来源风险项（risk_item_id）")
	}
	item, err := s.repo.Assessment.FindRiskItemByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrRiskItemNotFound) {
			return nil, errRiskItemNotFound()
		}
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询风险项失败", err)
	}
	return item, nil
}

// ensureNoActiveTicket 确认该 (资产, 漏洞) 没有未闭环单。
// excludeID > 0 时排除自身（本期没有调用点，留给将来「改挂到别的风险项」）。
func (s *RemediationService) ensureNoActiveTicket(
	ctx context.Context, assetID, vulnID, excludeID uint64,
) error {
	m, err := s.repo.Remediation.FindActiveByTarget(ctx, assetID, vulnID)
	if err != nil {
		if errors.Is(err, repository.ErrRemediationNotFound) {
			return nil
		}
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询已有整改单失败", err)
	}
	if excludeID != 0 && m.ID == excludeID {
		return nil
	}
	return errRemediationDuplicateActive()
}

// createWithLog 在同一事务里写单子与首条记录。
//
// 必须同一个事务：只写单子不写首条记录的话，详情页的时间线会是空的，
// 而「这张单子是什么时候、由谁建的」就成了唯一的空白 —— 偏偏这一条
// 最容易在「随手复制一段插入代码」时被漏掉，且不报错。
func (s *RemediationService) createWithLog(
	ctx context.Context, m *model.Remediation,
	principal *auth.Principal, action string,
) error {
	err := s.repo.Transaction(ctx, func(tx *repository.Repository) error {
		if err := tx.Remediation.Create(ctx, m); err != nil {
			return err
		}
		return tx.Remediation.CreateLog(ctx, &model.RemediationLog{
			RemediationID: m.ID,
			Action:        action,
			ToStatus:      string(m.Status),
			OperatorID:    principalID(principal),
			OperatorName:  principalName(principal),
		})
	})
	if err != nil {
		if isDuplicateKey(err) {
			return errRemediationDuplicateActive()
		}
		return wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"创建整改单失败", err)
	}
	return nil
}

// appendLog 追加一条记录。失败只记日志、不影响业务（与审计同一条原则）。
func (s *RemediationService) appendLog(
	ctx context.Context, id uint64, principal *auth.Principal,
	action, from, to, note string,
) {
	err := s.repo.Remediation.CreateLog(ctx, &model.RemediationLog{
		RemediationID: id,
		Action:        action,
		FromStatus:    from,
		ToStatus:      to,
		Note:          note,
		OperatorID:    principalID(principal),
		OperatorName:  principalName(principal),
	})
	if err != nil {
		// 不把业务改判为失败：写操作已经提交，改判会让用户以为没生效而重复提交，
		// 那比丢一条记录严重（同 auditor 的取舍）。
		s.logger.Error("整改单记录写入失败",
			"remediation_id", id, "action", action, "err", err)
	}
}

// resolveNames 批量取负责人 / 创建人显示名。
func (s *RemediationService) resolveNames(
	ctx context.Context, rows []model.Remediation,
) (map[uint64]string, error) {
	seen := make(map[uint64]struct{}, len(rows)*2)
	ids := make([]uint64, 0, len(rows)*2)
	add := func(p *uint64) {
		if p == nil {
			return
		}
		if _, ok := seen[*p]; ok {
			return
		}
		seen[*p] = struct{}{}
		ids = append(ids, *p)
	}
	for i := range rows {
		add(rows[i].AssigneeID)
		add(rows[i].CreatedBy)
	}

	names, err := s.repo.User.NamesByIDs(ctx, ids)
	if err != nil {
		return nil, wrapError(http.StatusInternalServerError, errcode.CodeInternal,
			"查询用户显示名失败", err)
	}
	return names, nil
}

// ------------------------------------------------------------------ 转换

// newRemediationFromItem 由风险项构造整改单（含全部快照列）。
func newRemediationFromItem(item *model.RiskItem, principal *auth.Principal) *model.Remediation {
	assessmentID := item.AssessmentID
	riskItemID := item.ID
	title := item.VulnTitle
	if r := []rune(title); len(r) > remediationTitleMaxRunes {
		title = string(r[:remediationTitleMaxRunes])
	}
	return &model.Remediation{
		AssetID:      item.AssetID,
		VulnID:       item.VulnID,
		AssessmentID: &assessmentID,
		RiskItemID:   &riskItemID,
		AssetName:    item.AssetName,
		AssetIP:      item.AssetIP,
		VulnTitle:    item.VulnTitle,
		VulnCVEIDs:   item.VulnCVEIDs,
		RiskLevel:    string(item.RiskLevel),
		RiskValueR:   item.RiskValue,
		Title:        title,
		Status:       model.RemediationPending,
		CreatedBy:    principalID(principal),
	}
}

// toRemediationView 组装视图（含算出来的时间态与状态机投影）。
func toRemediationView(
	m *model.Remediation, today time.Time, names map[uint64]string,
) RemediationView {
	v := RemediationView{
		ID:           m.ID,
		AssetID:      m.AssetID,
		VulnID:       m.VulnID,
		AssessmentID: m.AssessmentID,
		RiskItemID:   m.RiskItemID,
		AssetName:    m.AssetName,
		AssetIP:      m.AssetIP,
		VulnTitle:    m.VulnTitle,
		VulnCVEIDs:   m.VulnCVEIDs,
		RiskLevel:    m.RiskLevel,
		RiskValueR:   m.RiskValueR,
		Title:        m.Title,
		Description:  m.Description,
		Resolution:   m.Resolution,
		Status:       string(m.Status),
		AssigneeID:   m.AssigneeID,
		DueDate:      formatDate(m.DueDate),
		Transitions:  transitionOptions(m.Status),
		CreatedAt:    m.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    m.UpdatedAt.Format(time.RFC3339),
	}
	if m.AssigneeID != nil {
		v.AssigneeName = names[*m.AssigneeID]
	}
	if m.CreatedBy != nil {
		v.CreatedByName = names[*m.CreatedBy]
	}
	if m.ClosedAt != nil {
		s := m.ClosedAt.Format(time.RFC3339)
		v.ClosedAt = &s
	}

	v.Overdue, v.OverdueDays, v.DueInDays = deriveTiming(m, today)
	return v
}

// deriveTiming 计算逾期 / 剩余天数。
//
// 三条规则，每一条都对应一个具体的错误答案：
//
//  1. **只有未闭环的单才可能逾期。** 一张逾期三天才闭环的单子，
//     闭环之后不该再出现在「逾期」清单里 —— 那是过去的事，
//     而清单是给「现在要处理什么」用的。
//  2. **due_date 与今天都归一到零点再比。** 直接拿带时刻的 now 去比，
//     今天到期的单子从今天 00:00:01 起就算逾期，而正确语义是
//     「今天之内还不算逾期」。
//  3. **未设期限不等于逾期。** NULL 一律返回三者皆空，
//     否则「没设期限」的单子会全部涌进逾期数，把这个指标直接废掉。
func deriveTiming(m *model.Remediation, today time.Time) (overdue bool, overdueDays int, dueInDays *int) {
	if m.DueDate == nil || !m.Status.IsActive() {
		return false, 0, nil
	}
	loc := today.Location()
	due := time.Date(m.DueDate.Year(), m.DueDate.Month(), m.DueDate.Day(), 0, 0, 0, 0, loc)
	base := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, loc)

	days := daysBetween(base, due)
	if days < 0 {
		return true, -days, nil
	}
	d := days
	return false, 0, &d
}

// daysBetween 返回 from → to 之间的整天数（正数表示 to 在后）。
//
// 用 AddDate 逐日推进而不是 `to.Sub(from).Hours()/24`：夏令时切换那一天
// 只有 23 小时（或 25 小时），按小时折算会得到整整一天的偏差，
// 而偏差恰好落在「今天到期」与「昨天到期」之间 —— 也就是逾期的判定边界上。
// 本系统按本机时区运行，不能假设没有夏令时。
func daysBetween(from, to time.Time) int {
	if from.Equal(to) {
		return 0
	}
	step := 1
	if to.Before(from) {
		step = -1
	}
	days := 0
	for cur := from; !cur.Equal(to); {
		cur = cur.AddDate(0, 0, step)
		days += step
		// 防御：due_date 被写成一个离谱的年份（比如 9999 年）时不至于转圈。
		if days > 36500 || days < -36500 {
			break
		}
	}
	return days
}

// transitionOptions 把状态机投影成前端可直接渲染的选项。
func transitionOptions(from model.RemediationStatus) []RemediationTransitionOption {
	next := model.NextStatuses(from)
	out := make([]RemediationTransitionOption, 0, len(next))
	for _, to := range next {
		out = append(out, RemediationTransitionOption{
			ToStatus:     string(to),
			NoteRequired: noteRequired(from, to),
		})
	}
	return out
}

// noteRequired 判断一次流转是否必须填写说明。
//
// 三条规则，对应三类**结论性**动作：
//
//	→ closed      怎么修的（没有它，闭环只是一个状态变化）
//	→ accepted    为什么不修（风险接受必须有理由，否则等于无声地放弃）
//	resolved → in_progress   为什么不通过（打回的理由是整改工作的核心记录）
//
// ⚠️ 这个函数同时被**校验**（Transition）与**投影**（transitionOptions）
// 使用，这正是它必须是唯一实现的原因：若前端另写一份，
// 就会出现「界面没标必填、提交后被 400 拒绝」。
func noteRequired(from, to model.RemediationStatus) bool {
	if to == model.RemediationClosed || to == model.RemediationAccepted {
		return true
	}
	return from == model.RemediationResolved && to == model.RemediationInProgress
}

// nextStatusLabels 返回某状态可流转到的状态字符串（供错误文案）。
func nextStatusLabels(from model.RemediationStatus) []string {
	next := model.NextStatuses(from)
	out := make([]string, 0, len(next))
	for _, s := range next {
		out = append(out, string(s))
	}
	return out
}

// normalizeLevels 规范化等级列表并去重，同时校验取值合法。
//
// 空列表退化为「很高 + 高」：这是「刚算完一次评估，先把最该修的开了单」
// 这个最常见用法的默认值。让用户每次都手写一遍等级筛选没有意义。
//
// ⚠️ 非法等级**报错**而不是静默丢弃。丢弃的话，`["very_high","HIGH"]`
// 会悄悄变成只对「很高」建单，用户拿到一个「创建了 3 张」的结果，
// 却不知道「高」那一批为什么一条都没建。
func normalizeLevels(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{string(model.RiskLevelVeryHigh), string(model.RiskLevelHigh)}, nil
	}

	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		trimmed := strings.TrimSpace(raw)
		l := model.RiskLevel(trimmed)
		if !l.Valid() {
			return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
				"风险等级「"+trimmed+"」非法，只能是 "+levelNames())
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out, nil
}

// levelNames 返回全部合法风险等级的展示串（供错误文案）。
func levelNames() string {
	names := make([]string, 0, len(model.RiskLevels))
	for _, l := range model.RiskLevels {
		names = append(names, string(l))
	}
	return strings.Join(names, " / ")
}

// changeNote 把「改了哪些字段」写成一条记录说明。
//
// 复用 sortedKeys（与审计明细同一套排序），保证同一次改动在日志与审计里
// 的字段顺序一致——顺序抖动的两个列表会被当成两次不同的改动。
func changeNote(cols map[string]any) string {
	return "修改字段：" + strings.Join(sortedKeys(cols), "、")
}

// ------------------------------------------------------------------ 辅助

func checkRemediationText(field, value string, max int) error {
	if n := len([]rune(value)); n > max {
		return newError(http.StatusBadRequest, errcode.CodeInvalidParam,
			fmt.Sprintf("%s最多 %d 个字符（当前 %d）", field, max, n))
	}
	return nil
}

func parseDueDate(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	// 只接受日期。同时容许 RFC3339 是为了让 curl 用户能直接贴
	// 接口返回里的时间串——但**时刻部分会被丢掉**，因为库里存的是 DATE。
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
			return &d, nil
		}
	}
	return nil, newError(http.StatusBadRequest, errcode.CodeInvalidParam,
		"整改期限格式非法，应为 YYYY-MM-DD")
}

func formatDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format("2006-01-02")
	return &s
}

func remediationStatusStrings(ss []model.RemediationStatus) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}
