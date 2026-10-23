package blob

import (
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello full body")
	ref, err := store.Put(data)
	if err != nil {
		t.Fatal(err)
	}
	if ref == "" {
		t.Fatal("empty ref")
	}
	got, err := store.Get(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q", got)
	}
	if _, err := os.Stat(store.path(ref)); err != nil {
		t.Fatalf("blob file missing: %v", err)
	}
	// 相同内容应复用同一引用。
	again, err := store.Put(data)
	if err != nil || again != ref {
		t.Fatalf("again=%q err=%v", again, err)
	}
}

func TestMemoryStore(t *testing.T) {
	store, _ := New("")
	ref, _ := store.Put([]byte("memory"))
	got, err := store.Get(ref)
	if err != nil || string(got) != "memory" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	store.Delete(ref)
	if _, err := store.Get(ref); err == nil {
		t.Fatal("expected missing blob")
	}
}

func TestDecodeGzip(t *testing.T) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, _ = writer.Write([]byte(`{"ok":true}`))
	_ = writer.Close()

	decoded, ok := Decode(buf.Bytes(), "gzip")
	if !ok || string(decoded) != `{"ok":true}` {
		t.Fatalf("decoded=%q ok=%v", decoded, ok)
	}
	if _, ok := Decode(buf.Bytes(), "br"); ok {
		t.Fatal("br should not be decoded")
	}
	if got := DecodeLimited(buf.Bytes(), "gzip", 5); string(got) != `{"ok"` {
		t.Fatalf("limited = %q", got)
	}
}
