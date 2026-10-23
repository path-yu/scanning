package store

import (
	"fmt"
	"testing"
	"time"

	"scanning/internal/flow"
)

func makeFlow(host string) *flow.Flow {
	return &flow.Flow{
		Host:       host,
		Method:     "GET",
		Path:       "/",
		StatusCode: 200,
		ReqSize:    10,
		RespSize:   20,
		StartedAt:  time.Now(),
	}
}

func TestRingAddGetPatch(t *testing.T) {
	r := NewRing(10, "s1")
	added := r.Add(makeFlow("a.example.com"))
	if added.ID == "" || added.Seq != 1 {
		t.Fatalf("unexpected added flow: %+v", added)
	}
	if added.SessionID != "s1" {
		t.Fatalf("session = %q", added.SessionID)
	}

	got, ok := r.Get(added.ID)
	if !ok || got.ID != added.ID {
		t.Fatalf("Get failed: %+v, %v", got, ok)
	}

	note := "hello"
	tags := []string{"a", "b"}
	pinned := true
	patched, ok := r.Patch(added.ID, flow.Patch{Note: &note, Tags: &tags, Pinned: &pinned})
	if !ok || patched.Note != note || len(patched.Tags) != 2 || !patched.Pinned {
		t.Fatalf("Patch failed: %+v, %v", patched, ok)
	}
}

func TestRingListOrderAndCursor(t *testing.T) {
	r := NewRing(10, "s1")
	for i := 0; i < 5; i++ {
		r.Add(makeFlow(fmt.Sprintf("h%d", i)))
	}

	items, hasMore, total := r.List(nil, 0, 3, false)
	if len(items) != 3 || !hasMore || total != 5 {
		t.Fatalf("asc page1: len=%d hasMore=%v total=%d", len(items), hasMore, total)
	}
	if items[0].Seq != 1 || items[2].Seq != 3 {
		t.Fatalf("unexpected seq: %d..%d", items[0].Seq, items[2].Seq)
	}

	items, hasMore, _ = r.List(nil, items[2].Seq, 3, false)
	if len(items) != 2 || hasMore {
		t.Fatalf("asc page2: len=%d hasMore=%v", len(items), hasMore)
	}
	if items[0].Seq != 4 {
		t.Fatalf("page2 first seq = %d", items[0].Seq)
	}

	desc, _, _ := r.List(nil, 0, 2, true)
	if len(desc) != 2 || desc[0].Seq != 5 || desc[1].Seq != 4 {
		t.Fatalf("desc page: %+v", []int64{desc[0].Seq, desc[1].Seq})
	}
}

func TestRingEvictionAndClear(t *testing.T) {
	r := NewRing(2, "s1")
	r.Add(makeFlow("a"))
	r.Add(makeFlow("b"))
	r.Add(makeFlow("c"))

	if r.Stats().Count != 2 || r.Stats().Evicted != 1 {
		t.Fatalf("stats = %+v", r.Stats())
	}
	if _, ok := r.Get("missing"); ok {
		t.Fatal("missing flow should not exist")
	}

	if n := r.Clear(); n != 2 {
		t.Fatalf("clear count = %d", n)
	}
	if r.Stats().Count != 0 {
		t.Fatalf("after clear stats = %+v", r.Stats())
	}

	next := r.Add(makeFlow("d"))
	if next.Seq != 1 {
		t.Fatalf("after clear seq = %d", next.Seq)
	}
}

func TestRingReplacePreservesSeqAndAnnotations(t *testing.T) {
	r := NewRing(10, "s1")
	added := r.Add(makeFlow("a"))
	note := "keep"
	tags := []string{"user"}
	pinned := true
	r.Patch(added.ID, flow.Patch{Note: &note, Tags: &tags, Pinned: &pinned})

	update := makeFlow("a")
	update.ID = added.ID
	update.StatusCode = 500
	update.State = flow.StateCompleted
	update.RespSize = 99
	updated, ok := r.Replace(update)
	if !ok {
		t.Fatal("Replace failed")
	}
	if updated.Seq != added.Seq || updated.StatusCode != 500 {
		t.Fatalf("updated = %+v", updated)
	}
	if updated.Note != note || !updated.Pinned || len(updated.Tags) != 1 {
		t.Fatalf("annotations lost: %+v", updated)
	}
	if r.Stats().Bytes != update.ReqSize+update.RespSize {
		t.Fatalf("bytes = %d", r.Stats().Bytes)
	}
	if _, ok := r.Replace(makeFlow("missing")); ok {
		t.Fatal("replace of evicted flow should fail")
	}
}

func TestRingRestore(t *testing.T) {
	r := NewRing(10, "s2")
	first := makeFlow("a")
	first.ID = "flow-a"
	second := makeFlow("b")
	second.ID = "flow-b"
	count := r.Restore([]*flow.Flow{first, second})
	if count != 2 {
		t.Fatalf("restore count = %d", count)
	}
	got, ok := r.Get("flow-a")
	if !ok || got.Seq != 1 || got.SessionID != "s2" {
		t.Fatalf("restored = %+v ok=%v", got, ok)
	}
	third := r.Add(makeFlow("c"))
	if third.Seq != 3 {
		t.Fatalf("seq after restore = %d", third.Seq)
	}
}
