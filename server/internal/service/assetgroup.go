package service

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"secrisk/server/internal/auth"
	"secrisk/server/internal/config"
	"secrisk/server/internal/model"
	"secrisk/server/internal/pkg/errcode"
	"secrisk/server/internal/repository"
)

const assetGroupNameMaxRunes = 64

// maxAssetGroupDepthValue 是 depth 字段（0 基）允许的最大值。
//
// model.MaxAssetGroupDepth 说的是「最多几层」，而 depth 从 0 开始，
// 因此合法区间是 0 .. Max-1。这个 -1 极容易在某个分支里漏掉，
// 所以只在这里算一次。
const maxAssetGroupDepthValue = model.MaxAssetGroupDepth - 1

// AssetGroupView 资产组的对外视图。
//
// 树形结构由 Children 承载，而 `List` 接口只返回根节点数组——
// 前端拿到后可以直接喂给 el-tree，不必自己拼父子关系。
type AssetGroupView struct {
	ID       uint64  `json:"id"`
	ParentID *uint64 `json:"parent_id"`
	Name     string  `json:"name"`
	// Path 物化路径。对外暴露而非隐藏：它是「按子树筛选资产」时
	// 前端能自己判断从属关系的依据，也方便运维对照数据库排查。
	Path string `json:"path"`
	// Depth 0 基层级，根组为 0。
	Depth       uint32 `json:"depth"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
	// AssetCount 直属该组的资产数量。
	AssetCount int64 `json:"asset_count"`
	// TotalAssetCount 含子树的资产合计。
	//
	// 两个数字都给出，是因为界面要回答两个不同的问题：删这个组会不会
	// 被拦住（看总数量），以及点进这个组能看到几条（看直属于它的数量）。
	TotalAssetCount int64            `json:"total_asset_count"`
	Children        []AssetGroupView `json:"children"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// CreateAssetGroupInput 新建资产组入参。
type CreateAssetGroupInput struct {
	ParentID    *uint64
	Name        string
	Description string
	SortOrder   *int
}

// UpdateAssetGroupInput 编辑资产组入参。全部字段用指针：nil 表示本次不修改。
//
// 刻意**不包含** ParentID：移动是独立端点（POST /asset-groups/{id}/move）。
// 混在一起的话「把组移到根」与「不移动」在 JSON 里都是 parent_id 缺失，
// 无法区分——除非引入 0 这个魔法值，而那会让契约变得需要额外解释。
type UpdateAssetGroupInput struct {
	Name        *string
	Description *string
	SortOrder   *int
}

// AssetGroupService 资产组服务。
type AssetGroupService struct {
	cfg    *config.Config
	repo   *repository.Repository
	audit  *auditor
	logger *slog.Logger
}

// NewAssetGroupService 构建资产组服务。
func NewAssetGroupService(
	cfg *config.Config, repo *repository.Repository, logger *slog.Logger,
) *AssetGroupService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AssetGroupService{
		cfg: cfg, repo: repo, audit: newAuditor(repo, logger), logger: logger,
	}
}

// Tree 返回完整的资产组树。
func (s *AssetGroupService) Tree(ctx context.Context) ([]AssetGroupView, error) {
	groups, err := s.repo.AssetGroup.ListAll(ctx)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询资产组失败", err)
	}
	counts, err := s.repo.Asset.GroupCounts(ctx)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "统计资产组资产数量失败", err)
	}

	byID := make(map[uint64]*AssetGroupView, len(groups))
	childrenOf := make(map[uint64][]*AssetGroupView, len(groups))
	var roots []*AssetGroupView

	for i := range groups {
		g := &groups[i]
		v := &AssetGroupView{
			ID:          g.ID,
			ParentID:    g.ParentID,
			Name:        g.Name,
			Path:        g.Path,
			Depth:       g.Depth,
			Description: g.Description,
			SortOrder:   g.SortOrder,
			AssetCount:  counts[g.ID],
			CreatedAt:   g.CreatedAt,
			UpdatedAt:   g.UpdatedAt,
		}
		byID[g.ID] = v
		if g.ParentID == nil {
			roots = append(roots, v)
			continue
		}
		childrenOf[*g.ParentID] = append(childrenOf[*g.ParentID], v)
	}

	// 同级按 sort_order 排，相同则按 id。
	// 排序键里带 id 是为了消除「两条记录 sort_order 都是 0」时
	// MySQL 返回顺序不确定的问题——列表在两次刷新之间换序会被当成 bug。
	for _, kids := range childrenOf {
		sort.Slice(kids, func(i, j int) bool {
			if kids[i].SortOrder != kids[j].SortOrder {
				return kids[i].SortOrder < kids[j].SortOrder
			}
			return kids[i].ID < kids[j].ID
		})
	}
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].SortOrder != roots[j].SortOrder {
			return roots[i].SortOrder < roots[j].SortOrder
		}
		return roots[i].ID < roots[j].ID
	})

	// 自底向上组装并累加子树资产数。
	// 递归深度受 model.MaxAssetGroupDepth 约束（最多 8 层），不会栈溢出。
	var assemble func(v *AssetGroupView) int64
	assemble = func(v *AssetGroupView) int64 {
		kids := childrenOf[v.ID]
		v.Children = make([]AssetGroupView, 0, len(kids))
		total := v.AssetCount
		for _, kid := range kids {
			total += assemble(kid)
			v.Children = append(v.Children, *kid)
		}
		v.TotalAssetCount = total
		return total
	}

	out := make([]AssetGroupView, 0, len(roots))
	for _, r := range roots {
		assemble(r)
		out = append(out, *r)
	}
	return out, nil
}

// Create 新建资产组。
func (s *AssetGroupService) Create(
	ctx context.Context, in CreateAssetGroupInput,
	operator *auth.Principal, meta RequestMeta,
) (*AssetGroupView, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, newError(400, errcode.CodeInvalidParam, "资产组名称不能为空")
	}
	if len([]rune(name)) > assetGroupNameMaxRunes {
		return nil, newError(400, errcode.CodeInvalidParam, "资产组名称不得超过 64 个字符")
	}
	description := strings.TrimSpace(in.Description)
	if len([]rune(description)) > 255 {
		return nil, newError(400, errcode.CodeInvalidParam, "说明不得超过 255 个字符")
	}

	var parentPath string
	depth := uint32(0)
	if in.ParentID != nil {
		parent, err := s.repo.AssetGroup.FindByID(ctx, *in.ParentID)
		if err != nil {
			if errors.Is(err, repository.ErrAssetGroupNotFound) {
				return nil, errAssetGroupNotFound()
			}
			return nil, wrapError(500, errcode.CodeInternal, "创建资产组失败", err)
		}
		parentPath = parent.Path
		depth = parent.Depth + 1
		if depth > maxAssetGroupDepthValue {
			return nil, errAssetGroupDepthExceeded()
		}
	}

	exists, err := s.repo.AssetGroup.ExistsNameUnderParent(ctx, in.ParentID, name, 0)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "创建资产组失败", err)
	}
	if exists {
		return nil, errAssetGroupNameTaken()
	}

	g := &model.AssetGroup{
		ParentID:    in.ParentID,
		Name:        name,
		Depth:       depth,
		Description: description,
	}
	if in.SortOrder != nil {
		g.SortOrder = *in.SortOrder
	}
	if operator != nil {
		creator := operator.UserID
		g.CreatedBy = &creator
	}

	if err := s.repo.AssetGroup.Create(ctx, g, parentPath); err != nil {
		// 并发下由唯一索引兜底：两个请求同时建同名同级组时，
		// 前置检查会双双通过。
		if isDuplicateKey(err) {
			return nil, errAssetGroupNameTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "创建资产组失败", err)
	}

	view := toAssetGroupView(g)
	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetGroupCreate,
		"asset_group", strconv.FormatUint(g.ID, 10), map[string]any{
			"name":      name,
			"parent_id": in.ParentID,
			"path":      g.Path,
		}))

	return &view, nil
}

// Update 编辑资产组的名称、说明与排序。
func (s *AssetGroupService) Update(
	ctx context.Context, id uint64, in UpdateAssetGroupInput,
	operator *auth.Principal, meta RequestMeta,
) (*AssetGroupView, error) {
	current, err := s.repo.AssetGroup.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssetGroupNotFound) {
			return nil, errAssetGroupNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "更新资产组失败", err)
	}

	fields := make(map[string]any, 3)
	changed := make([]string, 0, 3)

	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, newError(400, errcode.CodeInvalidParam, "资产组名称不能为空")
		}
		if len([]rune(name)) > assetGroupNameMaxRunes {
			return nil, newError(400, errcode.CodeInvalidParam, "资产组名称不得超过 64 个字符")
		}
		if name != current.Name {
			exists, err := s.repo.AssetGroup.ExistsNameUnderParent(ctx, current.ParentID, name, id)
			if err != nil {
				return nil, wrapError(500, errcode.CodeInternal, "更新资产组失败", err)
			}
			if exists {
				return nil, errAssetGroupNameTaken()
			}
		}
		fields["name"] = name
		changed = append(changed, "name")
	}

	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if len([]rune(description)) > 255 {
			return nil, newError(400, errcode.CodeInvalidParam, "说明不得超过 255 个字符")
		}
		fields["description"] = description
		changed = append(changed, "description")
	}

	if in.SortOrder != nil {
		fields["sort_order"] = *in.SortOrder
		changed = append(changed, "sort_order")
	}

	if len(fields) == 0 {
		view := toAssetGroupView(current)
		return &view, nil
	}
	fields["updated_at"] = time.Now()

	if err := s.repo.AssetGroup.Update(ctx, id, fields); err != nil {
		if isDuplicateKey(err) {
			return nil, errAssetGroupNameTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "更新资产组失败", err)
	}

	updated, err := s.repo.AssetGroup.FindByID(ctx, id)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "更新资产组失败", err)
	}
	view := toAssetGroupView(updated)

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetGroupUpdate,
		"asset_group", strconv.FormatUint(id, 10), map[string]any{
			"name":   updated.Name,
			"fields": changed,
			"path":   updated.Path,
		}))

	return &view, nil
}

// Move 把资产组挂到新的父组下（parentID 为 nil 表示移到根）。
//
// 这是本文件里唯一会写多行的操作：物化路径的特性决定了移动一个节点
// 必须重写整棵子树。因此校验也最严——
//
//  1. **防环**：不能把组挂到它自己的子孙之下，否则那部分节点会从树上脱落，
//     既不在任何根下，也永远无法通过界面找到。
//  2. **防超深**：搬过去之后最深的那个后代必须仍在层数上限内。
//     只查「新父的深度 + 1」是不够的——被搬的可能是一棵三层子树。
//  3. **防重名**：新父组下不能已有同名子组（唯一索引兜底，但先查一次
//     才能给出可读的错误码）。
func (s *AssetGroupService) Move(
	ctx context.Context, id uint64, parentID *uint64,
	operator *auth.Principal, meta RequestMeta,
) (*AssetGroupView, error) {
	current, err := s.repo.AssetGroup.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssetGroupNotFound) {
			return nil, errAssetGroupNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "移动资产组失败", err)
	}

	var newParentPath string
	newDepth := uint32(0)
	if parentID != nil {
		if *parentID == id {
			return nil, errAssetGroupCycle()
		}
		parent, err := s.repo.AssetGroup.FindByID(ctx, *parentID)
		if err != nil {
			if errors.Is(err, repository.ErrAssetGroupNotFound) {
				return nil, errAssetGroupNotFound()
			}
			return nil, wrapError(500, errcode.CodeInternal, "移动资产组失败", err)
		}
		// 防环判据：新父的物化路径以「自身路径」为前缀，说明新父是自身的后代。
		//
		// 路径末尾的斜杠在这里起了关键作用：「/1/4/」不是「/1/41/」的前缀，
		// 因此同层相邻的 4 号与 41 号不会被误判为父子关系。
		// 若省略末尾斜杠，这个判断会在 ID 位数变化时出错。
		if strings.HasPrefix(parent.Path, current.Path) {
			return nil, errAssetGroupCycle()
		}
		newParentPath = parent.Path
		newDepth = parent.Depth + 1
	}

	// 被搬动的整棵子树里最深的那一层，搬完之后会到哪儿
	maxDepthInSubtree, err := s.repo.AssetGroup.MaxDepthInSubtree(ctx, current.Path)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "移动资产组失败", err)
	}
	depthDelta := int(newDepth) - int(current.Depth)
	if int(maxDepthInSubtree)+depthDelta > int(maxAssetGroupDepthValue) {
		return nil, errAssetGroupDepthExceeded()
	}

	exists, err := s.repo.AssetGroup.ExistsNameUnderParent(ctx, parentID, current.Name, id)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "移动资产组失败", err)
	}
	if exists {
		return nil, errAssetGroupNameTaken()
	}

	// 挂父与其子树重写必须同事务：中间失败会留下一棵路径与 parent_id
	// 互不一致的树，而那种数据靠人工很难修回来。
	newPrefix := newParentPath + strconv.FormatUint(id, 10) + "/"
	err = s.repo.Transaction(ctx, func(txRepo *repository.Repository) error {
		if err := txRepo.AssetGroup.Update(ctx, id, map[string]any{
			"parent_id":  parentID,
			"updated_at": time.Now(),
		}); err != nil {
			return err
		}
		return txRepo.AssetGroup.MoveSubtree(ctx, current.Path, newPrefix, depthDelta)
	})
	if err != nil {
		if isDuplicateKey(err) {
			return nil, errAssetGroupNameTaken()
		}
		return nil, wrapError(500, errcode.CodeInternal, "移动资产组失败", err)
	}

	moved, err := s.repo.AssetGroup.FindByID(ctx, id)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "移动资产组失败", err)
	}
	view := toAssetGroupView(moved)

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetGroupMove,
		"asset_group", strconv.FormatUint(id, 10), map[string]any{
			"name":        current.Name,
			"from_path":   current.Path,
			"to_path":     moved.Path,
			"new_parent":  parentID,
			"depth_delta": depthDelta,
		}))

	return &view, nil
}

// Delete 删除资产组。
//
// 两道前置检查都必须做，且顺序不能反：先看子组，再看资产。
// 反过来的话，一个既有子组又有资产的组会报「里面还有资产」，
// 而用户把资产移走后仍然删不掉——多一轮无效往返。
func (s *AssetGroupService) Delete(
	ctx context.Context, id uint64, operator *auth.Principal, meta RequestMeta,
) error {
	current, err := s.repo.AssetGroup.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrAssetGroupNotFound) {
			return errAssetGroupNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "删除资产组失败", err)
	}

	children, err := s.repo.AssetGroup.CountChildren(ctx, id)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "删除资产组失败", err)
	}
	if children > 0 {
		return errAssetGroupHasChildren()
	}

	// 判据是「这棵子树里有没有资产」。虽然子组不允许存在（上面已拦住），
	// 因此查子树与查自己等价，但保留子树语义可以让将来放宽
	// 「不允许有子组」这条限制时，这段逻辑仍然正确。
	//
	// 传 current.Path 而不是 id：物化路径的前缀是完整祖先链，
	// 详见 SubtreeIDsByPath 的说明。
	ids, err := s.repo.AssetGroup.SubtreeIDsByPath(ctx, current.Path)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "删除资产组失败", err)
	}
	n, err := s.repo.Asset.CountByGroupIDs(ctx, ids)
	if err != nil {
		return wrapError(500, errcode.CodeInternal, "删除资产组失败", err)
	}
	if n > 0 {
		return errAssetGroupHasAssets(n)
	}

	if err := s.repo.AssetGroup.Delete(ctx, id); err != nil {
		if errors.Is(err, repository.ErrAssetGroupNotFound) {
			return errAssetGroupNotFound()
		}
		return wrapError(500, errcode.CodeInternal, "删除资产组失败", err)
	}

	s.audit.record(ctx, auditEntryFor(operator, meta, model.ActionAssetGroupDelete,
		"asset_group", strconv.FormatUint(id, 10), map[string]any{
			"name": current.Name,
			"path": current.Path,
		}))

	return nil
}

// ResolveGroupFilter 把「按资产组筛选」展开成资产组 ID 集合。
//
// 导出给资产服务与导入流程复用。返回 nil 表示「不限分组」。
//
// 语义是**含子树**：选中「华东区」时用户期望看到它下面所有机房的资产，
// 而不是只有直接挂在「华东区」上的那几条。这一点必须由后端实现——
// 前端拿不到完整的父子关系（树是懒加载的话更拿不到）。
func (s *AssetGroupService) ResolveGroupFilter(
	ctx context.Context, groupID uint64, includeChildren bool,
) ([]uint64, error) {
	if groupID == 0 {
		return nil, nil
	}
	// 先确认组存在：不确认的话，一个不存在的 group_id 会静默返回空列表，
	// 用户看到「没有数据」而以为是筛选条件的问题，实际上是组不存在。
	// 顺带取出 current.Path —— 展开子树需要的是路径而不是 ID。
	current, err := s.repo.AssetGroup.FindByID(ctx, groupID)
	if err != nil {
		if errors.Is(err, repository.ErrAssetGroupNotFound) {
			return nil, errAssetGroupNotFound()
		}
		return nil, wrapError(500, errcode.CodeInternal, "查询资产组失败", err)
	}
	if !includeChildren {
		return []uint64{groupID}, nil
	}

	ids, err := s.repo.AssetGroup.SubtreeIDsByPath(ctx, current.Path)
	if err != nil {
		return nil, wrapError(500, errcode.CodeInternal, "查询资产组失败", err)
	}
	return ids, nil
}

func toAssetGroupView(g *model.AssetGroup) AssetGroupView {
	return AssetGroupView{
		ID:          g.ID,
		ParentID:    g.ParentID,
		Name:        g.Name,
		Path:        g.Path,
		Depth:       g.Depth,
		Description: g.Description,
		SortOrder:   g.SortOrder,
		// Children 用非 nil 空切片：JSON 里是 [] 而不是 null，
		// 前端少写一处空值判断。
		Children:  []AssetGroupView{},
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
	}
}
