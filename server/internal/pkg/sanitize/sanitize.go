// Package sanitize 提供审计明细的敏感字段剔除。
//
// 独立成包的原因：中间件（自动记录写操作）与 service 层（记录认证事件）
// 都需要在序列化前清洗一遍明细，集中一处可避免两份规则逐渐走样。
//
// 定位是「最后一道防线」而非「唯一防线」：调用方本就不该把密码放进明细，
// 这里兜的是「某天有人不小心这么做了」。
package sanitize

import (
	"encoding/json"
	"strings"
)

// sensitiveKeys 敏感字段名（统一转小写后比对）。
var sensitiveKeys = map[string]struct{}{
	"password":         {},
	"old_password":     {},
	"new_password":     {},
	"confirm_password": {},
	"password_hash":    {},
	"token":            {},
	"access_token":     {},
	"refresh_token":    {},
	"csrf_token":       {},
	"secret":           {},
	"shared_secret":    {},
	"jwt_secret":       {},
	"authorization":    {},
	"cookie":           {},
}

// Redacted 替换后的占位文本。
const Redacted = "[REDACTED]"

// Detail 递归剔除 map / slice 中的敏感字段。
//
// 只处理 map[string]any 与 []any 这两种由 JSON 反序列化产生的形态；
// 结构体请先转成 map，否则剔除规则不会生效。
func Detail(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if _, bad := sensitiveKeys[strings.ToLower(k)]; bad {
				out[k] = Redacted
				continue
			}
			out[k] = Detail(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Detail(val)
		}
		return out
	default:
		return v
	}
}

// JSON 清洗并序列化明细，失败时返回 nil（调用方据此记录空明细）。
//
// 注意：返回 nil 而不是 panic 或报错——审计明细缺失不应该影响业务流程。
func JSON(v any) []byte {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(Detail(v))
	if err != nil {
		return nil
	}
	return raw
}
