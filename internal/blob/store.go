package blob

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Store 按内容寻址保存完整报文正文。dir 为空时仅保存在内存中，主要用于测试。
type Store struct {
	mu  sync.RWMutex
	dir string
	mem map[string][]byte
}

func New(dir string) (*Store, error) {
	s := &Store{dir: dir, mem: make(map[string][]byte)}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建正文目录 %s: %w", dir, err)
	}
	return s, nil
}

func (s *Store) Put(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	sum := sha256.Sum256(data)
	ref := hex.EncodeToString(sum[:])

	if s.dir == "" {
		s.mu.Lock()
		s.mem[ref] = append([]byte(nil), data...)
		s.mu.Unlock()
		return ref, nil
	}

	path := s.path(ref)
	if info, err := os.Stat(path); err == nil && info.Size() >= 0 {
		return ref, nil
	}

	tmp, err := os.CreateTemp(s.dir, ref+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("创建正文临时文件: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("写入正文: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("关闭正文文件: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// 并发写入同一内容时目标文件可能已存在，视为成功。
		if _, statErr := os.Stat(path); statErr == nil {
			return ref, nil
		}
		return "", fmt.Errorf("保存正文: %w", err)
	}
	if runtime.GOOS == "windows" {
		_ = os.Chmod(path, 0o600)
	}
	return ref, nil
}

func (s *Store) Get(ref string) ([]byte, error) {
	if ref == "" {
		return nil, os.ErrNotExist
	}
	if s.dir == "" {
		s.mu.RLock()
		data, ok := s.mem[ref]
		s.mu.RUnlock()
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), data...), nil
	}
	data, err := os.ReadFile(s.path(ref))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GetLimited 读取正文并最多返回 limit 字节，避免全文搜索时把超大正文全部载入内存。
func (s *Store) GetLimited(ref string, limit int64) ([]byte, error) {
	if ref == "" {
		return nil, os.ErrNotExist
	}
	if limit <= 0 {
		return s.Get(ref)
	}
	if s.dir == "" {
		s.mu.RLock()
		data, ok := s.mem[ref]
		s.mu.RUnlock()
		if !ok {
			return nil, os.ErrNotExist
		}
		if int64(len(data)) > limit {
			data = data[:limit]
		}
		return append([]byte(nil), data...), nil
	}
	file, err := os.Open(s.path(ref))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(io.LimitReader(file, limit))
}

func (s *Store) Delete(ref string) {
	if ref == "" {
		return
	}
	if s.dir == "" {
		s.mu.Lock()
		delete(s.mem, ref)
		s.mu.Unlock()
		return
	}
	_ = os.Remove(s.path(ref))
}

func (s *Store) path(ref string) string {
	return filepath.Join(s.dir, ref)
}

// Decode 按 Content-Encoding 解压正文。raw 为 false 时表示编码不受支持或解压失败。
func Decode(data []byte, encoding string) (out []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return data, true
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		defer func() { _ = reader.Close() }()
		out, err = io.ReadAll(reader)
		return out, err == nil
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(data))
		if err == nil {
			defer func() { _ = reader.Close() }()
			out, err = io.ReadAll(reader)
			return out, err == nil
		}
		flateReader := flate.NewReader(bytes.NewReader(data))
		defer func() { _ = flateReader.Close() }()
		out, err = io.ReadAll(flateReader)
		return out, err == nil
	default:
		return nil, false
	}
}

// DecodeLimited 解压正文并最多返回 limit 字节，避免巨大的压缩炸弹占满内存。
func DecodeLimited(data []byte, encoding string, limit int64) []byte {
	if limit <= 0 {
		limit = 256 << 10
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		if int64(len(data)) > limit {
			return data[:limit]
		}
		return data
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil
		}
		defer func() { _ = reader.Close() }()
		out, _ := io.ReadAll(io.LimitReader(reader, limit))
		return out
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			reader = flate.NewReader(bytes.NewReader(data))
		}
		defer func() { _ = reader.Close() }()
		out, _ := io.ReadAll(io.LimitReader(reader, limit))
		return out
	default:
		return nil
	}
}
