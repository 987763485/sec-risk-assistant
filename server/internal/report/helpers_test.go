package report

import (
	"fmt"
	"testing"
	"time"
)

// testThresholds 与出厂配置一致（20/12/6/2）。
var testThresholds = Thresholds{VeryHigh: 20, High: 12, Medium: 6, Low: 2}

// testData 构造一份 5×5 = 25 条风险项的完整报告数据。
//
// 刻意用「5 档重要性 × 5 档严重程度」铺满：矩阵天然是满的，
// 等级分布也覆盖多个档位，渲染器的循环与边界都能被走到。
func testData() ReportData {
	const threatWeight = 3.0

	levelOf := func(r float64) string {
		// 测试自己的判定，不复用被测代码的任何函数
		switch {
		case r >= float64(testThresholds.VeryHigh):
			return LevelVeryHigh
		case r >= float64(testThresholds.High):
			return LevelHigh
		case r >= float64(testThresholds.Medium):
			return LevelMedium
		case r >= float64(testThresholds.Low):
			return LevelLow
		default:
			return LevelVeryLow
		}
	}

	var (
		items     []ItemRow
		seq       int
		maxRisk   float64
		levelCnts = map[string]int{}
		matrixRaw = map[[2]uint8]struct {
			count int64
			maxR  float64
		}{}
	)

	for imp := uint8(1); imp <= 5; imp++ {
		for sev := uint8(1); sev <= 5; sev++ {
			seq++
			a := float64(imp)
			v := float64(sev)
			r := a * threatWeight * v
			level := levelOf(r)

			items = append(items, ItemRow{
				Seq:        seq,
				AssetName:  fmt.Sprintf("E2E-ASSET-%d", imp),
				AssetIP:    fmt.Sprintf("192.168.9.%d", imp),
				VulnTitle:  fmt.Sprintf("E2E 漏洞 S=%d", sev),
				ThreatName: "E2E 威胁 T=3",
				Importance: imp,
				Severity:   sev,
				A:          a,
				T:          threatWeight,
				V:          v,
				R:          r,
				RiskLevel:  level,
			})

			levelCnts[level]++
			if r > maxRisk {
				maxRisk = r
			}

			key := [2]uint8{imp, sev}
			cur := matrixRaw[key]
			cur.count++
			if r > cur.maxR {
				cur.maxR = r
			}
			matrixRaw[key] = cur
		}
	}

	// 资产汇总：每台资产取名下最大 R
	assets := make([]AssetRow, 0, 5)
	for imp := uint8(1); imp <= 5; imp++ {
		var best float64
		for sev := uint8(1); sev <= 5; sev++ {
			r := float64(imp) * threatWeight * float64(sev)
			if r > best {
				best = r
			}
		}
		assets = append(assets, AssetRow{
			Name:       fmt.Sprintf("E2E-ASSET-%d", imp),
			IP:         fmt.Sprintf("192.168.9.%d", imp),
			Importance: imp,
			ValueA:     float64(imp),
			RiskValue:  best,
			RiskLevel:  levelOf(best),
			ItemsCount: 5,
		})
	}

	// 25 格矩阵
	cells := make([]MatrixCell, 0, 25)
	var total int64
	for _, sev := range []uint8{1, 2, 3, 4, 5} {
		for _, imp := range []uint8{1, 2, 3, 4, 5} {
			raw := matrixRaw[[2]uint8{imp, sev}]
			cells = append(cells, MatrixCell{
				Importance: imp,
				Severity:   sev,
				Count:      raw.count,
				MaxRisk:    raw.maxR,
				Level:      levelOf(raw.maxR),
			})
			total += raw.count
		}
	}

	at := time.Date(2026, 10, 11, 13, 30, 0, 0, time.Local)
	for _, level := range LevelOrder {
		if _, ok := levelCnts[level]; !ok {
			levelCnts[level] = 0
		}
	}

	return ReportData{
		Title:       "E2E 信息系统网络安全风险评估报告",
		Subtitle:    "评估依据：GB/T 20984 相乘法",
		GeneratedAt: at,
		GeneratedBy: "admin",
		Assessment: AssessmentInfo{
			ID:                7,
			Name:              "E2E 评估（P5 报告）",
			Description:       "用于验证报告导出链路",
			ScopeType:         "all",
			DefaultThreatName: "E2E 威胁 T=3",
			AssetsCount:       5,
			RiskItemsCount:    25,
			CalculatedAt:      "2026-10-11 13:00:00",
		},
		Config: ConfigInfo{
			Model:       "gb_t_20984_multiplication",
			AssetWeight: 1.0,
			Thresholds:  testThresholds,
			CapturedAt:  at,
		},
		LevelCounts: levelCnts,
		MaxRisk:     maxRisk,
		Assets:      assets,
		Items:       items,
		Matrix: MatrixData{
			GridSize: 5,
			Total:    total,
			Cells:    cells,
		},
	}
}

// findSection 按标题取章节，取不到时让测试直接失败（而不是返回零值，
// 那样后续断言会在一个空章节上做，报错信息完全对不上问题）。
func findSection(t *testing.T, sections []docxSection, heading string) docxSection {
	t.Helper()
	for _, s := range sections {
		if s.Heading == heading {
			return s
		}
	}
	t.Fatalf("章节 %q 不存在；实际章节：%v", heading, sectionHeadings(sections))
	return docxSection{}
}

func sectionHeadings(sections []docxSection) []string {
	out := make([]string, 0, len(sections))
	for _, s := range sections {
		out = append(out, s.Heading)
	}
	return out
}
