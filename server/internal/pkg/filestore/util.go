package filestore

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// timeDirString 返回 YYYYMM 形式的子目录名。
//
// 单独拆成带注入点的函数没有收益——按月分目录只影响磁盘布局，
// 不影响正确性，测试直接接受当前月份即可。
func timeDirString() string {
	return time.Now().Format("200601")
}

// newUUID 生成 32 字符的 hex 随机串作为落盘文件名。
//
// 用 crypto/rand 而不是 google/uuid：这里要的只是一个不可预测、
// 不含路径分隔符的名字，crypto/rand 十行就够了。
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败意味着系统熵源出了根本性问题，
		// 此时继续写文件比失败更危险，直接 panic。
		panic("filestore: 系统熵源不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}
