// Package migrations 以内嵌方式携带 SQL 迁移文件。
//
// 用内嵌而非挂载目录，是为了让编译产物自包含：部署时不会因为漏拷
// migrations 目录而在启动阶段失败。
package migrations

import "embed"

// FS 内嵌的迁移文件集合，供 golang-migrate 的 iofs 源驱动读取。
//
//go:embed *.sql
var FS embed.FS
