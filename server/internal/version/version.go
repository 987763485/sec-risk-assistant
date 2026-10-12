// Package version 保存构建期注入的版本信息。
//
// 构建时通过 -ldflags 注入：
//
//	go build -ldflags "-X secrisk/server/internal/version.Version=1.2.3 \
//	  -X secrisk/server/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X secrisk/server/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

var (
	// Version 语义化版本号
	Version = "0.1.0"
	// Commit 构建时的 git commit（短哈希）
	Commit = "dev"
	// BuildTime UTC 构建时间
	BuildTime = "unknown"
)
