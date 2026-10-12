package filestore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T, maxBytes int64) *Store {
	t.Helper()
	s, err := New(t.TempDir(), maxBytes)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSaveAndOpenRoundtrip(t *testing.T) {
	s := newTestStore(t, 1<<20)
	content := []byte("nessus report content \x00\x01\x02 binary ok")

	saved, err := s.Save(strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// 相对路径形如 YYYYMM/<32hex>，不含用户输入的任何字符
	if n := strings.Count(saved.RelPath, string(filepath.Separator)); n != 1 {
		t.Errorf("相对路径应只有一层子目录，got %q", saved.RelPath)
	}
	// 哈希正确
	sum := sha256.Sum256(content)
	if saved.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 不匹配: got %s", saved.SHA256)
	}
	if saved.Size != int64(len(content)) {
		t.Errorf("Size 不匹配: got %d", saved.Size)
	}

	f, err := s.Open(saved.RelPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	got, _ := io.ReadAll(f)
	if string(got) != string(content) {
		t.Error("回读内容不一致")
	}
}

func TestSaveTooLarge(t *testing.T) {
	s := newTestStore(t, 8)
	_, err := s.Save(strings.NewReader("123456789")) // 9 字节 > 8
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("期望 ErrTooLarge，got %v", err)
	}
	// 超限失败不得留下任何临时文件
	entries, _ := os.ReadDir(filepath.Join(s.root, timeDirString()))
	if len(entries) != 0 {
		t.Errorf("超限失败后目录应干净，残留 %d 个文件", len(entries))
	}
}

func TestOpenRejectsTraversal(t *testing.T) {
	s := newTestStore(t, 1<<20)
	for _, p := range []string{"../../etc/passwd", "/etc/passwd", "..", "", "a/../../b"} {
		if _, err := s.Open(p); !errors.Is(err, ErrNotFound) {
			t.Errorf("路径 %q 应被拒绝为 ErrNotFound，got %v", p, err)
		}
	}
}

func TestOpenMissing(t *testing.T) {
	s := newTestStore(t, 1<<20)
	if _, err := s.Open("209901/deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("期望 ErrNotFound，got %v", err)
	}
}

func TestRemove(t *testing.T) {
	s := newTestStore(t, 1<<20)
	saved, err := s.Save(strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Remove(saved.RelPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// 再删一次：幂等，已不存在应返回 nil（清理残留时不卡死）
	if err := s.Remove(saved.RelPath); err != nil {
		t.Fatalf("重复删除应幂等返回 nil，got %v", err)
	}
}

func TestSaveIsDeterministicHashDifferentContent(t *testing.T) {
	s := newTestStore(t, 1<<20)
	a, _ := s.Save(strings.NewReader("aaa"))
	b, _ := s.Save(strings.NewReader("bbb"))
	if a.SHA256 == b.SHA256 {
		t.Error("不同内容的哈希不应相同")
	}
	if a.RelPath == b.RelPath {
		t.Error("不同内容的落盘路径不应相同")
	}
}
