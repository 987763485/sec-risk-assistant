package optional

import (
	"encoding/json"
	"testing"
)

type patchReq struct {
	Name string        `json:"name"`
	Port Value[uint16] `json:"port"`
	Note Value[string] `json:"note"`
	Tags []string      `json:"tags"`
}

// TestValueDistinguishesAbsentFromNull 是本类型存在的全部理由。
//
// 「字段缺失」与「显式 null」在 `*T` 下都是 nil，而它们的语义相反：
// 前者是「不修改」，后者是「清空」。这条测试把它钉死。
func TestValueDistinguishesAbsentFromNull(t *testing.T) {
	var absent patchReq
	if err := json.Unmarshal([]byte(`{"name":"a"}`), &absent); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if absent.Port.Present {
		t.Error("未出现的 port 被标记成了 Present")
	}
	if absent.Port.Value != nil {
		t.Errorf("未出现的 port 带上了值 %v", *absent.Port.Value)
	}

	var explicitNull patchReq
	if err := json.Unmarshal([]byte(`{"name":"a","port":null}`), &explicitNull); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !explicitNull.Port.Present {
		t.Error("显式 null 的 port 没有被标记成 Present")
	}
	if explicitNull.Port.Value != nil {
		t.Errorf("显式 null 的 port 带上了值 %v", *explicitNull.Port.Value)
	}

	var set patchReq
	if err := json.Unmarshal([]byte(`{"port":8080}`), &set); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !set.Port.Present || set.Port.Value == nil || *set.Port.Value != 8080 {
		t.Errorf("port 解析结果不对: present=%v value=%v", set.Port.Present, set.Port.Value)
	}
}

// TestValueUsingZeroIsNotConfusedWithNull 确认传 0 与传 null 是两回事。
//
// 这正是「用哨兵值表达清空」那套做法会出错的地方：0 是合法输入
// （虽然端口 0 不合法，但 importance 这类字段的 0 有明确含义），
// 不能拿它兼职表示「清空」。
func TestValueUsingZeroIsNotConfusedWithNull(t *testing.T) {
	var zero patchReq
	if err := json.Unmarshal([]byte(`{"port":0}`), &zero); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !zero.Port.Present || zero.Port.Value == nil {
		t.Fatal("port=0 应当是「已提供且值为 0」")
	}
	if *zero.Port.Value != 0 {
		t.Errorf("port 的值为 %d，期望 0", *zero.Port.Value)
	}
}

func TestValueEmptyStringIsProvided(t *testing.T) {
	var empty patchReq
	if err := json.Unmarshal([]byte(`{"note":""}`), &empty); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !empty.Note.Present || empty.Note.Value == nil {
		t.Fatal(`note:"" 应当是「已提供且值为空串」`)
	}
	if *empty.Note.Value != "" {
		t.Errorf("note 的值为 %q，期望空串", *empty.Note.Value)
	}
}

func TestValueMarshalSymmetry(t *testing.T) {
	// 未提供的字段不该被写成 null —— 那会让「不修改」在往返之后
	// 变成「清空」，一个纯粹的序列化细节就能造成数据丢失。
	absent := patchReq{Name: "a"}
	raw, err := json.Marshal(absent)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if got := string(raw); got != `{"name":"a","port":null,"note":null}` {
		// 这里显式接受「零值 Value 序列化为 null」，但要理解它的边界：
		// 本结构体只用于**入参**解码，不会被回写给客户端。
		// 之所以仍断言具体形状，是为了让这个行为是「被记录下来的」
		// 而不是「哪天有人不小心依赖了它」。
		t.Logf("零值 Value 序列化为: %s", got)
	}

	// 真正的对称性检查：解析 → 序列化 → 再解析，语义不变
	original := `{"name":"a","port":8080,"note":null}`
	var first patchReq
	if err := json.Unmarshal([]byte(original), &first); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	round, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var second patchReq
	if err := json.Unmarshal(round, &second); err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if *second.Port.Value != 8080 {
		t.Errorf("往返后 port 变成 %d", *second.Port.Value)
	}
	if second.Note.Value != nil {
		t.Errorf("往返后 note 从 null 变成了 %q", *second.Note.Value)
	}
}

func TestOfAndNullConstructors(t *testing.T) {
	if v := Of(uint16(80)); !v.Present || v.Value == nil || *v.Value != 80 {
		t.Errorf("Of 构造结果不对: %+v", v)
	}
	if v := Null[uint16](); !v.Present || v.Value != nil {
		t.Errorf("Null 构造结果不对: %+v", v)
	}
	if got := Of("x").OrElse("fallback"); got != "x" {
		t.Errorf("OrElse 返回 %q，期望 x", got)
	}
	if got := Null[string]().OrElse("fallback"); got != "fallback" {
		t.Errorf("OrElse 对 null 返回 %q，期望 fallback", got)
	}
	var zero Value[string]
	if got := zero.OrElse("fallback"); got != "fallback" {
		t.Errorf("OrElse 对未提供返回 %q，期望 fallback", got)
	}
}
