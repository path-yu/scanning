package persist

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanning/internal/flow"
)

func TestSaveLoadRoundTripAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	session := flow.Session{
		ID:        "s1",
		Name:      "测试会话",
		Mode:      flow.ModeMixed,
		Filter:    "host:example.com",
		CreatedAt: time.Now(),
		ByteCount: 128,
	}
	flows := []*flow.Flow{
		{ID: "f1", Seq: 1, Host: "a.example.com", Method: "GET", Path: "/1", StatusCode: 200, Tags: []string{}, StartedAt: time.Now()},
		{ID: "f2", Seq: 2, Host: "b.example.com", Method: "POST", Path: "/2", StatusCode: 500, Tags: []string{"x"}, StartedAt: time.Now()},
	}
	saved, err := db.Save(context.Background(), session, flows)
	if err != nil {
		t.Fatal(err)
	}
	if saved.FlowCount != 2 || !saved.Persistent {
		t.Fatalf("saved = %+v", saved)
	}

	list, err := db.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}

	loaded, items, err := db.Load(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "测试会话" || len(items) != 2 || items[1].ID != "f2" {
		t.Fatalf("loaded=%+v items=%d", loaded, len(items))
	}

	// 模拟重启：关闭后重新打开应仍能读取。
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	list, err = reopened.List(context.Background())
	if err != nil || len(list) != 1 || list[0].FlowCount != 2 {
		t.Fatalf("reopened list=%+v err=%v", list, err)
	}
	_, items, err = reopened.Load(context.Background(), "s1")
	if err != nil || len(items) != 2 {
		t.Fatalf("reopened load err=%v len=%d", err, len(items))
	}

	deleted, err := reopened.Delete(context.Background(), "s1")
	if err != nil || !deleted {
		t.Fatalf("delete=%v err=%v", deleted, err)
	}
	if _, _, err := reopened.Load(context.Background(), "s1"); !os.IsNotExist(err) {
		t.Fatalf("expected not exist, got %v", err)
	}
}
