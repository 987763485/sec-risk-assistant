// Package filestore 负责上传文件在磁盘上的存取。
//
// 它只回答一个问题：「这坨字节放到哪里、怎么拿回来」，不知道数据库的
// 存在——scan_files 表的元数据归 repository 管。两者以 storage_path
// （相对路径）为握手点，filestore 拿到相对路径就能读能删。
//
// 安全约定（上传基线的落点，见 docs/01 §2.3 第 3 条）：
//   - 存储路径由本包生成，永远不含用户输入的任何字符（文件名 UUID 化），
//     从根上消除路径穿越；
//   - 写入用「临时名 + rename」：进程被杀时不会留下半截文件被当作
//     完整文件读走——半截的 xlsx 同样是 zip，魔数校验拦不住它。
package filestore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Store 上传文件存储。
type Store struct {
	// root 落盘根目录（绝对化后的 storage.upload_dir）。
	root string
	// maxBytes 单文件体积上限。超限直接拒绝，不读完整内容。
	maxBytes int64
}

// New 创建存储。root 会被绝对化；目录在首次写入时按需创建（MkdirAll），
// 构造函数不碰磁盘，方便测试。
func New(root string, maxBytes int64) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("filestore: 存储根目录不能为空")
	}
	if maxBytes <= 0 {
		return nil, errors.New("filestore: 单文件体积上限必须为正数")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("filestore: 解析根目录失败: %w", err)
	}
	return &Store{root: abs, maxBytes: maxBytes}, nil
}

// MaxBytes 返回单文件体积上限。
func (s *Store) MaxBytes() int64 { return s.maxBytes }

// ErrTooLarge 文件体积超过上限。
var ErrTooLarge = errors.New("filestore: 文件体积超过上限")

// ErrNotFound 相对路径对应的文件不存在。
var ErrNotFound = errors.New("filestore: 文件不存在")

// Saved 一次成功落盘的结果。
type Saved struct {
	// RelPath 相对路径，形如 202610/<uuid>。这是与 scan_files 表的握手点。
	RelPath string
	// SHA256 内容哈希（hex）。
	SHA256 string
	// Size 字节数。
	Size int64
}

// Save 把 r 的内容落盘，返回相对路径与哈希。
//
// 流式处理：哈希与落盘在同一次遍历里完成，不为大文件造内存副本。
// 超过 maxBytes 立即失败——注意此时临时文件已被清理，不会留下垃圾。
func (s *Store) Save(r io.Reader) (*Saved, error) {
	// 先落成一个完整的临时文件，哈希算完、体积核完再 rename 到位。
	// 临时文件与最终文件放同一目录，保证 rename 是同文件系统内的原子操作。
	monthDir := filepath.Join(s.root, timeDirString())
	if err := os.MkdirAll(monthDir, 0o750); err != nil {
		return nil, fmt.Errorf("filestore: 创建存储目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(monthDir, ".upload-*")
	if err != nil {
		return nil, fmt.Errorf("filestore: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	// 任何一条失败路径都要清掉临时文件；成功路径会把 rename 走掉，Remove 落空无害。
	defer func() { _ = os.Remove(tmpName) }()

	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(r, s.maxBytes+1))
	closeErr := tmp.Close()
	if err != nil {
		return nil, fmt.Errorf("filestore: 写入失败: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("filestore: 关闭临时文件失败: %w", closeErr)
	}
	if size > s.maxBytes {
		return nil, ErrTooLarge
	}

	rel := filepath.Join(timeDirString(), newUUID())
	final := filepath.Join(s.root, rel)
	if err := os.Rename(tmpName, final); err != nil {
		return nil, fmt.Errorf("filestore: 落盘失败: %w", err)
	}
	return &Saved{
		RelPath: rel,
		SHA256:  hex.EncodeToString(hasher.Sum(nil)),
		Size:    size,
	}, nil
}

// Open 打开相对路径对应的文件。
//
// 入参必须是本包 Save 返回的相对路径（来自数据库，不是用户输入）；
// 即便如此仍做一次穿越检查——万一未来有人把用户可控字符串传进来，
// 这里是最后一道闸。
func (s *Store) Open(relPath string) (*os.File, error) {
	full, ok := s.resolve(relPath)
	if !ok {
		return nil, ErrNotFound
	}
	f, err := os.Open(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: 打开文件失败: %w", err)
	}
	return f, nil
}

// Remove 删除相对路径对应的文件。
//
// 幂等：文件已不存在时返回 nil。调用方（删除服务）在「记录已删、
// 物理文件已不在」这种残留状态下应当继续，而不是卡死；
// 真正的 IO 错误（权限、磁盘）照常上抛。
func (s *Store) Remove(relPath string) error {
	full, ok := s.resolve(relPath)
	if !ok {
		return ErrNotFound
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("filestore: 删除文件失败: %w", err)
	}
	return nil
}

// resolve 把相对路径解析为根目录下的绝对路径，并拒绝一切逃逸。
func (s *Store) resolve(relPath string) (string, bool) {
	if relPath == "" {
		return "", false
	}
	clean := filepath.Clean(relPath)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", false
	}
	full := filepath.Join(s.root, clean)
	// 双保险：Join 后再验证一次前缀（符号链接等极端情形由运行环境保证，
	// 上传目录不出现在任何软链路径下是部署约束，写在部署文档里）。
	if full != s.root && !strings.HasPrefix(full, s.root+string(filepath.Separator)) {
		return "", false
	}
	return full, true
}
