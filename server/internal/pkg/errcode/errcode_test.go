package errcode

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// codeOKConstantName 是唯一允许不出现在 allCodes 里的错误码常量。
//
// 它的取值 "OK" 只出现在**成功**信封的 code 字段，而不是任何错误响应，
// 而 allCodes 的语义是「错误码注册表」，因此收进来反而是错的。
const codeOKConstantName = "CodeOK"

// TestAllCodesCoversEveryConstant 核对「声明的错误码常量」与「注册表」一致。
//
// 用 go/ast 解析本包源码而不是维护一份手写清单：手写清单本身就是第三个
// 需要同步的地方，而这道测试要防的恰恰是「加了常量忘了同步」。
//
// 两个方向的漂移都要拦：
//   - 常量加了、allCodes 没加 → 契约里不会有这个码，前端无法针对它分支；
//   - allCodes 里有个不存在的值 → 契约会声明一个后端永远不返回的码。
func TestAllCodesCoversEveryConstant(t *testing.T) {
	declared := declaredCodeConstants(t)

	registered := make(map[string]string, len(allCodes))
	duplicated := make([]string, 0, 2)
	for _, code := range allCodes {
		if first, dup := registered[code]; dup {
			duplicated = append(duplicated, code+"（同时挂在 "+first+" 与另一个常量上）")
			continue
		}
		registered[code] = code
	}
	if len(duplicated) > 0 {
		sort.Strings(duplicated)
		t.Fatalf("allCodes 存在重复项：%s", strings.Join(duplicated, "、"))
	}

	// 方向一：每个常量是否都已登记
	var missing []string
	for name, value := range declared {
		if name == codeOKConstantName {
			continue
		}
		if _, ok := registered[value]; !ok {
			missing = append(missing, name+" = "+value)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("以下错误码常量没有登记进 allCodes，前端契约里将看不到它们：\n  %s",
			strings.Join(missing, "\n  "))
	}

	// 方向二：注册表里的每个值是否都对应一个真实常量
	known := make(map[string]struct{}, len(declared))
	for _, value := range declared {
		known[value] = struct{}{}
	}
	var phantom []string
	for code := range registered {
		if _, ok := known[code]; !ok {
			phantom = append(phantom, code)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("allCodes 里有 %d 个值不对应任何常量（可能是拼写错误），"+
			"契约会声明后端永不返回的码：\n  %s",
			len(phantom), strings.Join(phantom, "\n  "))
	}
}

// TestDeclaredCodeConstantsWereParsed 保证解析逻辑本身没失效。
//
// 上面那道测试在「一个常量都没解析到」时会**全部通过**（两个方向的
// 差集都是空集），这是最典型的静默失效。这里用一个下限把它钉住。
func TestDeclaredCodeConstantsWereParsed(t *testing.T) {
	declared := declaredCodeConstants(t)
	if len(declared) < 30 {
		t.Fatalf("只解析到 %d 个错误码常量，远少于当前规模，解析逻辑很可能失效了",
			len(declared))
	}
	if _, ok := declared[codeOKConstantName]; !ok {
		t.Fatalf("没有解析到 %s，解析逻辑失效", codeOKConstantName)
	}
}

// TestAllReturnsCopy 确认 All 返回的是副本。
//
// 契约校验测试会遍历它的结果；若拿到的是原切片，任意一次意外写入都会
// 污染全局注册表，而这类污染极难定位。
func TestAllReturnsCopy(t *testing.T) {
	first := All()
	if len(first) == 0 {
		t.Fatal("All 返回了空列表")
	}
	original := first[0]
	first[0] = "MUTATED"
	if got := All()[0]; got != original {
		t.Fatalf("All 返回的不是副本：改写返回值影响了内部注册表（%q → %q）", original, got)
	}
}

// declaredCodeConstants 解析本包源码，返回 `CodeXxx = "..."` 形式的常量表。
func declaredCodeConstants(t *testing.T) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		// 排除测试文件自身，避免把测试里造的假常量也算进来
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析包目录失败: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("期望恰好解析到 1 个包，实际 %d 个", len(pkgs))
	}

	declared := make(map[string]string)
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				spec, ok := n.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range spec.Names {
					// 只认错误码常量：以 Code 开头
					if !strings.HasPrefix(name.Name, "Code") {
						continue
					}
					// 只认显式的字符串字面量赋值（本包全部常量都是这种形式）。
					// iota 那类省略值的写法这里没有，遇到了也只会被跳过，
					// 由 TestDeclaredCodeConstantsWereParsed 的下限兜住。
					if i >= len(spec.Values) {
						continue
					}
					lit, ok := spec.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("常量 %s 的字面量无法解析: %v", name.Name, err)
					}
					declared[name.Name] = value
				}
				return true
			})
		}
	}
	return declared
}
