// Package optional 提供「三态字段」的 JSON 解码。
//
// ▍它解决什么问题
//
// PATCH 语义里，一个可空字段有三种状态，而朴素写法只能表达两种：
//
//	{"port": 8080}  设为 8080
//	{"port": null}  清空        ← 与「不传」在 Go 里都是 nil
//	{}              不修改      ↑
//
// 用 `*uint16` 时后两者无法区分，于是「清空端口」这个操作用户怎么点都
// 不生效，而接口看起来一切正常——这是最难排查的一类缺陷。
//
// ▍为什么不用哨兵值
//
// 另一种常见做法是约定「传 0 表示清空」。它能用，但会把一个纯实现细节
// 泄漏到对外契约里：`port` 的 schema 就得写 `minimum: 0`，而 0 不是合法
// 端口，读者必须先去翻文档才知道它是魔法值。三态类型让契约可以诚实地写成
// `type: [integer, "null"]`，并且「不传」在 JSON 里本来就区别于 null。
//
// ▍用法
//
//	port optional.Value[uint16]  // 在请求结构体里
//	if port.Present {            // 字段出现在请求里了
//	    if port.Value == nil {   // 显式 null → 清空
//	...
package optional

import "encoding/json"

// Value 表示一个可能未提供、可能为 null 的字段。
type Value[T any] struct {
	// Present 字段是否出现在 JSON 中。
	Present bool
	// Value 字段的值；nil 表示显式传了 null。
	//
	// Present 为 false 时 Value 恒为 nil，但两者含义完全不同：
	// 前者是「不修改」，后者是「清空」。
	Value *T
}

// UnmarshalJSON 实现 json.Unmarshaler。
//
// 只要这个方法被调用，就说明键存在——encoding/json 对未出现的键
// 不会调用解码器。这正是 Present 的判据来源，也是本类型成立的基础。
func (v *Value[T]) UnmarshalJSON(data []byte) error {
	v.Present = true
	if string(data) == "null" {
		v.Value = nil
		return nil
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	v.Value = &out
	return nil
}

// MarshalJSON 实现 json.Marshaler，保证回写与读入对称。
//
// 没有它的话，序列化会输出 `{"Present":true,"Value":...}` —— 一旦某个
// 地方不小心把这个结构体直接返回给客户端，契约就悄悄变了。
func (v Value[T]) MarshalJSON() ([]byte, error) {
	if v.Value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*v.Value)
}

// Of 构造一个「已提供且非 null」的值。
func Of[T any](value T) Value[T] {
	return Value[T]{Present: true, Value: &value}
}

// Null 构造一个「显式传 null」的值（即清空）。
func Null[T any]() Value[T] {
	return Value[T]{Present: true, Value: nil}
}

// OrElse 返回字段值；未提供或为 null 时返回默认值。
// 供只需要「读一个值」的场景使用，例如新建接口里的可选字段。
func (v Value[T]) OrElse(fallback T) T {
	if v.Value == nil {
		return fallback
	}
	return *v.Value
}
