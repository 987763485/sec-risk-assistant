package router

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"secrisk/server/internal/apidoc"
	"secrisk/server/internal/pkg/errcode"
)

// openAPIPath 契约文件相对本测试包的位置。
//
//	go test 的工作目录是包目录（internal/router），因此上溯三层到仓库根。
const openAPIPath = "../../../docs/openapi.yaml"

// TestOpenAPISpecIsValid 校验手写的契约文件本身没有结构性错误。
//
// 覆盖的是「手写 spec 最容易出的错」：悬空 $ref、漏写 operationId、
// 路径模板变量没有对应参数声明、安全方案名字写错、误用 3.0 的 nullable、
// 定义了却从未被引用的 schema。
func TestOpenAPISpecIsValid(t *testing.T) {
	spec, err := apidoc.Load(filepath.FromSlash(openAPIPath))
	if err != nil {
		t.Fatalf("加载 OpenAPI 契约失败: %v", err)
	}

	if problems := spec.Validate(); len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("契约问题: %v", p)
		}
		t.Fatalf("OpenAPI 契约存在 %d 个问题", len(problems))
	}

	t.Logf("契约结构校验通过，共 %d 条路径、%d 个操作",
		len(spec.Paths), len(spec.Operations()))
}

// TestSpecAndRouterAreInSync 是本文件的核心：把契约与真实路由表**双向**比对。
//
// 单向检查是不够的，两个方向各自代表一类事故：
//
//	① 路由有、spec 没有  → 新接口悄悄上线，前端与调用方无从知晓，
//	                      契约沦为「部分文档」，比没有契约更误导
//	② spec 有、路由没有  → 接口被删或改名，契约残留成幽灵端点，
//	                      前端照着它写代码，联调时才发现 404
//
// 这个测试因此同时替代了「文档是否过期」与「是否有未登记接口」两项人工评审。
func TestSpecAndRouterAreInSync(t *testing.T) {
	spec, err := apidoc.Load(filepath.FromSlash(openAPIPath))
	if err != nil {
		t.Fatalf("加载 OpenAPI 契约失败: %v", err)
	}

	// ── 真实路由表（规范化路径语法后） ────────────────────────────────
	actual := map[string]struct{}{}
	for _, route := range testRouter(t).Routes() {
		// gin 会为部分 GET 自动补充 HEAD，这不是独立的业务端点
		if route.Method == "HEAD" {
			continue
		}
		actual[route.Method+" "+apidoc.NormalizeGinPath(route.Path)] = struct{}{}
	}

	declared := spec.RouteSet()

	// ── 方向 ①：路由存在但契约未登记 ─────────────────────────────────
	var missing []string
	for key := range actual {
		if _, ok := declared[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		t.Errorf("路由 %q 已实现但未写入 docs/openapi.yaml —— "+
			"新增接口必须同步补契约，否则前端与调用方无从知晓", key)
	}

	// ── 方向 ②：契约登记但路由不存在 ─────────────────────────────────
	var ghost []string
	for key := range declared {
		if _, ok := actual[key]; !ok {
			ghost = append(ghost, key)
		}
	}
	sort.Strings(ghost)
	for _, key := range ghost {
		t.Errorf("契约中的 %q 在路由表里不存在 —— "+
			"接口已删除或改名，契约残留为幽灵端点", key)
	}

	if len(missing) == 0 && len(ghost) == 0 {
		t.Logf("契约与路由表完全对齐，共 %d 个端点", len(declared))
	}
}

// requiresAuth 判断契约中的某个操作是否要求**登录态**。
//
// 判据是「security 里是否出现 SessionCookie」，而不是「security 是否为空」。
// 这两件事必须分开：登录、刷新、登出无需登录即可调用，但**必须**携带
// CSRF 令牌，因此它们的 security 非空却仍属于公开端点。
// 若把「security 非空」当作「需要认证」，校验规则会与 router.PublicRoute
// 直接自相矛盾——那正是把两个概念混为一谈的典型症状。
func requiresAuth(op apidoc.Operation) bool {
	security, _ := op.Raw["security"].([]any)
	for _, req := range security {
		reqMap, _ := req.(map[string]any)
		if _, ok := reqMap["SessionCookie"]; ok {
			return true
		}
	}
	return false
}

// hasSecurityRequirement 判断契约中的某个操作是否声明了任何 security 要求。
//
// 与 requiresAuth 的差别在于它把 CSRF 也算进去：用来说明「这个端点
// 虽然不需要登录，但也不是随便就能调用」。
func hasSecurityRequirement(op apidoc.Operation) bool {
	security, ok := op.Raw["security"].([]any)
	return ok && len(security) > 0
}

// TestContractCoversEveryPermissionGuard 确认契约里标注了每条受保护路由的访问要求。
//
// 这条规则拦的是「接口实现了权限校验，但契约里写成公开」这类文档事故：
// 前端会误以为可以直接调用，联调时收获一堆 403。
func TestContractCoversEveryPermissionGuard(t *testing.T) {
	spec, err := apidoc.Load(filepath.FromSlash(openAPIPath))
	if err != nil {
		t.Fatalf("加载 OpenAPI 契约失败: %v", err)
	}

	public := publicSet()

	for _, op := range spec.Operations() {
		_, isPublic := public[op.RouteKey()]

		if isPublic && requiresAuth(op) {
			t.Errorf("%s 是公开端点，但契约声明了 SessionCookie 要求", op.RouteKey())
		}
		if !isPublic && !requiresAuth(op) {
			t.Errorf("%s 需要认证，但契约未声明 SessionCookie —— 前端会误以为可直接调用",
				op.RouteKey())
		}
	}
}

// TestWriteEndpointsRequireCSRF 确认契约把所有写请求都标上了 CSRF 要求。
//
// 对应服务端的真实行为：/api 分组下所有非安全方法都会先过 CSRF 中间件。
// 契约里漏标会让前端在联调时被 403 挡住，而错误提示只说「CSRF 校验失败」，
// 排查方向反而被引向服务端配置。
func TestWriteEndpointsRequireCSRF(t *testing.T) {
	spec, err := apidoc.Load(filepath.FromSlash(openAPIPath))
	if err != nil {
		t.Fatalf("加载 OpenAPI 契约失败: %v", err)
	}

	safeMethods := map[string]struct{}{"GET": {}, "HEAD": {}, "OPTIONS": {}}

	for _, op := range spec.Operations() {
		if _, safe := safeMethods[op.Method]; safe {
			continue
		}

		hasCSRF := false
		security, _ := op.Raw["security"].([]any)
		for _, req := range security {
			reqMap, _ := req.(map[string]any)
			if _, ok := reqMap["CSRFToken"]; ok {
				hasCSRF = true
				break
			}
		}
		if !hasCSRF {
			t.Errorf("%s 是写请求，契约必须声明 CSRFToken 安全要求", op.RouteKey())
		}
		if !hasSecurityRequirement(op) {
			t.Errorf("%s 是写请求，契约的 security 不应为空", op.RouteKey())
		}
	}
}

// TestPublicEndpointsMatchWhitelist 反向确认契约里的公开端点与代码白名单一致。
//
// 契约把某个端点写成公开、而代码实际挂了认证 → 前端会踩 403；
// 反之则更危险：契约声称需要认证、代码却忘了挂中间件。
// 这条测试与 PublicRoute 清单绑定，两者任一变动都会被发现。
func TestPublicEndpointsMatchWhitelist(t *testing.T) {
	spec, err := apidoc.Load(filepath.FromSlash(openAPIPath))
	if err != nil {
		t.Fatalf("加载 OpenAPI 契约失败: %v", err)
	}

	public := publicSet()

	var specPublic []string
	for _, op := range spec.Operations() {
		if !requiresAuth(op) {
			specPublic = append(specPublic, op.RouteKey())
		}
	}

	for _, key := range specPublic {
		if _, ok := public[key]; !ok {
			t.Errorf("契约把 %q 声明为公开端点，但它不在 router.PublicRoute 白名单中", key)
		}
	}

	// 白名单里的端点必须在契约里同样是公开的
	for key := range public {
		found := false
		for _, sp := range specPublic {
			if sp == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("router.PublicRoute 中的 %q 在契约里未声明为公开端点", key)
		}
	}
}

// publicSet 把公开清单转成规范化后的 RouteKey 集合。
func publicSet() map[string]struct{} {
	out := make(map[string]struct{}, len(PublicRoute))
	for _, entry := range PublicRoute {
		method, path, ok := strings.Cut(entry, " ")
		if !ok {
			continue
		}
		out[method+" "+apidoc.NormalizeGinPath(path)] = struct{}{}
	}
	return out
}

// TestErrorCodeEnumCoversRegistry 双向核对契约的 ErrorCode 枚举与后端注册表。
//
// 两个方向各自对应一类事故：
//
//	① 注册表有、契约没有 → 前端生成的联合类型里没有这个码，运行时会落进
//	   「未知错误码」分支，用户看到的是一句通用提示而不是专门的处理
//	② 契约有、注册表没有 → 契约里出现永远拿不到的幽灵码，调用方会为它写
//	   处理逻辑，而那段逻辑永远不会执行
//
// 两种漏法方向相反，因此必须双向比。errcode.go 的包注释里写着这条测试
// 存在——注释承诺的护栏必须真的存在，否则它比没有注释更糟。
func TestErrorCodeEnumCoversRegistry(t *testing.T) {
	spec, err := apidoc.Load(filepath.FromSlash(openAPIPath))
	if err != nil {
		t.Fatalf("加载 OpenAPI 契约失败: %v", err)
	}

	declared := enumValues(t, spec, "ErrorCode")
	// 防「解析逻辑失效导致两边都是空集、测试静默全绿」
	if len(declared) < 20 {
		t.Fatalf("只解析到 %d 个错误码，枚举解析可能已经失效", len(declared))
	}

	inDeclared := make(map[string]struct{}, len(declared))
	for _, c := range declared {
		inDeclared[c] = struct{}{}
	}
	inRegistry := make(map[string]struct{})
	registered := errcode.All()
	for _, c := range registered {
		inRegistry[c] = struct{}{}
	}

	for _, c := range registered {
		if _, ok := inDeclared[c]; !ok {
			t.Errorf("错误码 %q 已在后端注册，但未写入契约的 ErrorCode 枚举 —— "+
				"前端生成的类型里不会有它，只能落到通用错误分支", c)
		}
	}
	for _, c := range declared {
		if _, ok := inRegistry[c]; !ok {
			t.Errorf("契约的 ErrorCode 枚举里有 %q，但后端注册表里没有 —— "+
				"这是一个永远不会被返回的幽灵码", c)
		}
	}
}

// enumValues 取出某个 schema 的 enum 取值（用于纯字符串枚举）。
func enumValues(t *testing.T, spec *apidoc.Spec, name string) []string {
	t.Helper()

	components, ok := spec.Root["components"].(map[string]any)
	if !ok {
		t.Fatal("契约里没有 components 节点")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		t.Fatal("契约里没有 components.schemas 节点")
	}
	schema, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("契约里没有名为 %q 的 schema", name)
	}
	raw, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("schema %q 没有 enum 节点（或类型不是数组）", name)
	}

	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("schema %q 的 enum 里出现了非字符串值 %v", name, v)
		}
		out = append(out, s)
	}
	return out
}
