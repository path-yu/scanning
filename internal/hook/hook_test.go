package hook

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeProxyAddr(t *testing.T) {
	cases := map[string]string{
		"":               "127.0.0.1:8899",
		"127.0.0.1:8899": "127.0.0.1:8899",
		"0.0.0.0:8899":   "127.0.0.1:8899",
		"[::]:8900":      "127.0.0.1:8900",
		"localhost:8899": "localhost:8899",
	}
	for input, want := range cases {
		if got := normalizeProxyAddr(input); got != want {
			t.Fatalf("normalizeProxyAddr(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizePorts(t *testing.T) {
	cases := []struct {
		input []int
		want  []int
	}{
		{nil, []int{80, 443}},
		{[]int{443, 80, 443}, []int{80, 443}},
		{[]int{0, -1, 70000, 8080}, []int{8080}},
	}
	for _, tc := range cases {
		if got := normalizePorts(tc.input); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("normalizePorts(%v) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestWriteUTF16File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook.ini")
	content := "[hook]\r\nproxy=127.0.0.1:8899\r\nports=80,443\r\n"
	if err := writeUTF16File(path, content); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[0] != 0xff || data[1] != 0xfe {
		t.Fatalf("缺少 UTF-16LE BOM: % x", data[:min(4, len(data))])
	}
	if len(data) != 2+len(content)*2 {
		t.Fatalf("文件长度 = %d, want %d", len(data), 2+len(content)*2)
	}
}

func TestResolveDLLExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanning_hook_x64.dll")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := resolveDLL(path)
	if !ok || got != path {
		t.Fatalf("resolveDLL(%q) = %q, %v", path, got, ok)
	}
}
