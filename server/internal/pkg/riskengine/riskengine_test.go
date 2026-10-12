package riskengine_test

import (
	"math"
	"testing"
	"time"

	"secrisk/server/internal/pkg/riskengine"
)

// wantLevel 用**真实值**独立判定等级，作为引擎定点实现的第二实现。
//
// 刻意不复用 riskengine.LevelOf：那条路径走的是放大 1000 倍的整数比较，
// 这里走 float 比较。两条路径对同一批输入给出同一批结论，才说明定标
// 没有把边界算错——用被测代码去验证被测代码等于什么都没验。
func wantLevel(r float64) string {
	switch {
	case r >= 20:
		return riskengine.LevelVeryHigh
	case r >= 12:
		return riskengine.LevelHigh
	case r >= 6:
		return riskengine.LevelMedium
	case r >= 2:
		return riskengine.LevelLow
	default:
		return riskengine.LevelVeryLow
	}
}

// TestComputeExhaustive 穷举 A / T / V 的全部 125 组取值。
//
// 挑几个边界值测是运气，穷举是证明。125 组跑完只要几毫秒——
// 而漏掉的那一组恰好是某个客户现场用的权重组合，才是真正的代价。
func TestComputeExhaustive(t *testing.T) {
	cfg := riskengine.DefaultConfig()

	cases := 0
	for a := uint8(1); a <= 5; a++ {
		for tw := 1.0; tw <= 5.0; tw++ {
			for v := uint8(1); v <= 5; v++ {
				cases++
				got := riskengine.Compute(cfg, riskengine.Input{
					Importance:   a,
					ThreatWeight: tw,
					Severity:     v,
				})

				wantR := float64(a) * tw * float64(v)
				if math.Abs(got.R-wantR) > 1e-9 {
					t.Fatalf("A=%d T=%g V=%d: R=%v，期望 %v", a, tw, v, got.R, wantR)
				}
				if got.A != float64(a) {
					t.Fatalf("A=%d T=%g V=%d: A=%v，期望 %v", a, tw, v, got.A, float64(a))
				}
				if got.V != float64(v) {
					t.Fatalf("A=%d T=%g V=%d: V=%v，期望 %v", a, tw, v, got.V, float64(v))
				}
				if want := wantLevel(wantR); got.Level != want {
					t.Fatalf("A=%d T=%g V=%d: R=%v 判成 %s，期望 %s",
						a, tw, v, got.R, got.Level, want)
				}
			}
		}
	}

	if cases != 125 {
		t.Fatalf("穷举了 %d 组，期望 125 组", cases)
	}
}

// TestComputeEndpoints 两个端点：最小值与最大值。
func TestComputeEndpoints(t *testing.T) {
	cfg := riskengine.DefaultConfig()

	min := riskengine.Compute(cfg, riskengine.Input{Importance: 1, ThreatWeight: 1, Severity: 1})
	if min.R != 1 {
		t.Fatalf("最小组合 R=%v，期望 1", min.R)
	}
	if min.Level != riskengine.LevelVeryLow {
		t.Fatalf("R=1 应判「很低」，实际 %s", min.Level)
	}

	max := riskengine.Compute(cfg, riskengine.Input{Importance: 5, ThreatWeight: 5, Severity: 5})
	if max.R != 125 {
		t.Fatalf("最大组合 R=%v，期望 125", max.R)
	}
	if max.Level != riskengine.LevelVeryHigh {
		t.Fatalf("R=125 应判「很高」，实际 %s", max.Level)
	}
}

// TestLevelBoundaries 阈值边界：每个档位的下界与下界减一。
//
// 定标错一位（比如误用 >）时，只有恰好落在边界的那些组合会错——
// 而它们正是「评审会上被抽查的那几个数」。
func TestLevelBoundaries(t *testing.T) {
	cfg := riskengine.DefaultConfig()

	// 用 A=T=1 时的 V 直接构造 R：A×T×V = V，于是 V 就是 R。
	tests := []struct {
		r    float64
		want string
	}{
		{1, riskengine.LevelVeryLow},
		{1.999, riskengine.LevelVeryLow}, // 判「低」的下界之下
		{2, riskengine.LevelLow},         // 下界本身必须判「低」
		{5.999, riskengine.LevelLow},
		{6, riskengine.LevelMedium},
		{11.999, riskengine.LevelMedium},
		{12, riskengine.LevelHigh},
		{19.999, riskengine.LevelHigh},
		{20, riskengine.LevelVeryHigh},
		{125, riskengine.LevelVeryHigh},
	}
	for _, tc := range tests {
		if got := riskengine.LevelOfValue(cfg, tc.r); got != tc.want {
			t.Errorf("R=%v 判成 %s，期望 %s", tc.r, got, tc.want)
		}
	}
}

// TestThresholdOrderMatters 判定必须从高到低。
//
// 从低到高判会让**所有**结果都落在最低档（第一个条件就命中）。
// 用一个同时满足全部四个阈值的 R 才能暴露顺序错误。
func TestThresholdOrderMatters(t *testing.T) {
	cfg := riskengine.DefaultConfig()
	if got := riskengine.LevelOfValue(cfg, 125); got != riskengine.LevelVeryHigh {
		t.Fatalf("R=125 判成 %s，说明判定顺序不是从高到低", got)
	}
}

// TestAssetWeightPropagation 资产价值权重系数的传导。
//
// 权重只作用于 A：改 1.5 倍，A 与 R 同步变 1.5 倍，T / V 不受影响。
func TestAssetWeightPropagation(t *testing.T) {
	cfg, err := riskengine.ParseConfig(1.5, 20, 12, 6, 2)
	if err != nil {
		t.Fatalf("构建配置失败: %v", err)
	}

	got := riskengine.Compute(cfg, riskengine.Input{Importance: 4, ThreatWeight: 5, Severity: 2})

	if math.Abs(got.A-6) > 1e-9 {
		t.Fatalf("A=%v，期望 4×1.5=6", got.A)
	}
	if got.T != 5 {
		t.Fatalf("T=%v，期望 5（权重不影响 T）", got.T)
	}
	if got.V != 2 {
		t.Fatalf("V=%v，期望 2（权重不影响 V）", got.V)
	}
	if math.Abs(got.R-60) > 1e-9 {
		t.Fatalf("R=%v，期望 6×5×2=60", got.R)
	}
	if got.Level != riskengine.LevelVeryHigh {
		t.Fatalf("R=60 应判「很高」，实际 %s", got.Level)
	}
}

// TestParseConfigRejectsInvalid 配置自相矛盾时必须在加载阶段拒绝。
//
// 这些组合如果放过去，引擎会算出一个「合法但无意义」的等级：
// 中间某一档永远为空，或者全部结果都落在最低档，而且不报任何错。
func TestParseConfigRejectsInvalid(t *testing.T) {
	tests := []struct {
		name                        string
		weight                      float64
		veryHigh, high, medium, low int
	}{
		{"权重为零", 0, 20, 12, 6, 2},
		{"权重为负", -1, 20, 12, 6, 2},
		{"权重过大", 101, 20, 12, 6, 2},
		{"阈值倒序", 1, 6, 12, 20, 2},
		{"阈值相等（很高=高）", 1, 20, 20, 6, 2},
		{"阈值相等（中=低）", 1, 20, 12, 6, 6},
		{"最低阈值为零", 1, 20, 12, 6, 0},
		{"最低阈值为负", 1, 20, 12, 6, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := riskengine.ParseConfig(tc.weight, tc.veryHigh, tc.high, tc.medium, tc.low); err == nil {
				t.Fatalf("期望拒绝，实际通过了")
			}
		})
	}
}

// TestParseConfigAcceptsSeeds 迁移 000001 预置的那组配置必须能通过校验。
//
// 这是「出厂配置自洽」的守门：种子数据一旦被改成倒序或重叠，
// 这条测试会立刻红，而不是等到算完一次评估才发现所有档位都不对。
func TestParseConfigAcceptsSeeds(t *testing.T) {
	cfg, err := riskengine.ParseConfig(1.0, 20, 12, 6, 2)
	if err != nil {
		t.Fatalf("出厂配置被拒绝: %v", err)
	}
	if cfg != riskengine.DefaultConfig() {
		t.Fatalf("解析出的配置与 DefaultConfig 不一致: %+v vs %+v", cfg, riskengine.DefaultConfig())
	}
}

// TestLevelRank 等级序数用于排序与比较，必须与 Levels 的顺序一致。
func TestLevelRank(t *testing.T) {
	if riskengine.LevelRank(riskengine.LevelVeryHigh) <= riskengine.LevelRank(riskengine.LevelHigh) {
		t.Fatal("「很高」的序数应大于「高」")
	}
	if riskengine.LevelRank(riskengine.LevelHigh) <= riskengine.LevelRank(riskengine.LevelMedium) {
		t.Fatal("「高」的序数应大于「中」")
	}
	if riskengine.LevelRank("不存在的等级") != 0 {
		t.Fatal("未知等级的序数应为 0")
	}
}

// TestSnapshotOf 快照记录的是人类可读的真实值。
//
// 存定点整数也能还原，但读的人得先知道 Scale 是多少——快照是证据，
// 证据的第一要求是「打开就能看懂」。
func TestSnapshotOf(t *testing.T) {
	cfg := riskengine.DefaultConfig()
	at := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)

	snap := riskengine.SnapshotOf(cfg, at)
	if snap.Model != riskengine.Name {
		t.Fatalf("模型标识=%s，期望 %s", snap.Model, riskengine.Name)
	}
	if snap.AssetWeight != 1.0 {
		t.Fatalf("权重=%v，期望 1.0", snap.AssetWeight)
	}
	if snap.Thresholds.VeryHigh != 20 || snap.Thresholds.Low != 2 {
		t.Fatalf("阈值=%+v，期望 very_high=20 low=2", snap.Thresholds)
	}
	if !snap.CapturedAt.Equal(at) {
		t.Fatalf("快照时间=%v，期望 %v", snap.CapturedAt, at)
	}
}
