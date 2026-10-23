package store

import (
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"scanning/internal/flow"
)

// Stats 是存储层的只读快照。
type Stats struct {
	Count    int   `json:"count"`
	Capacity int   `json:"capacity"`
	Bytes    int64 `json:"bytes"`
	Evicted  int64 `json:"evicted"`
}

type Ring struct {
	mu        sync.RWMutex
	slots     []*flow.Flow
	start     int
	count     int
	capacity  int
	byID      map[string]int
	nextSeq   int64
	sessionID string
	bytes     int64
	evicted   int64
}

func NewRing(capacity int, sessionID string) *Ring {
	if capacity <= 0 {
		capacity = 50000
	}
	return &Ring{
		slots:     make([]*flow.Flow, capacity),
		capacity:  capacity,
		byID:      make(map[string]int, capacity),
		sessionID: sessionID,
	}
}

func (r *Ring) Add(f *flow.Flow) *flow.Flow {
	if f == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if f.ID == "" {
		f.ID = ulid.Make().String()
	}
	if f.StartedAt.IsZero() {
		f.StartedAt = time.Now()
	}
	if f.Tags == nil {
		f.Tags = []string{}
	}
	f.SessionID = r.sessionID
	r.nextSeq++
	f.Seq = r.nextSeq

	var idx int
	if r.count == r.capacity {
		idx = r.start
		old := r.slots[idx]
		if old != nil {
			delete(r.byID, old.ID)
			r.bytes -= old.ReqSize + old.RespSize
			r.evicted++
		}
		r.slots[idx] = f
		r.start = (r.start + 1) % r.capacity
	} else {
		idx = (r.start + r.count) % r.capacity
		r.slots[idx] = f
		r.count++
	}
	r.byID[f.ID] = idx
	r.bytes += f.ReqSize + f.RespSize

	return f.Clone()
}

// Replace 用同一 ID 的新快照更新已存在的 Flow，保留排量与用户标注。
// 若 Flow 已被环形缓冲淘汰则返回 false。
func (r *Ring) Replace(f *flow.Flow) (*flow.Flow, bool) {
	if f == nil || f.ID == "" {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	idx, ok := r.byID[f.ID]
	if !ok {
		return nil, false
	}
	old := r.slots[idx]
	if old == nil || old.ID != f.ID {
		return nil, false
	}

	f.Seq = old.Seq
	f.SessionID = r.sessionID
	if f.Tags == nil {
		f.Tags = []string{}
	}
	// 合并用户在请求进行中写入的标注。
	if old.Note != "" && f.Note == "" {
		f.Note = old.Note
	}
	if old.Pinned {
		f.Pinned = true
	}
	if len(old.Tags) > 0 {
		seen := make(map[string]struct{}, len(f.Tags))
		for _, tag := range f.Tags {
			seen[tag] = struct{}{}
		}
		for _, tag := range old.Tags {
			if _, ok := seen[tag]; !ok {
				f.Tags = append(f.Tags, tag)
			}
		}
	}

	r.bytes -= old.ReqSize + old.RespSize
	r.bytes += f.ReqSize + f.RespSize
	r.slots[idx] = f
	return f.Clone(), true
}

// Restore 清空环形缓冲并按顺序恢复一批 Flow（用于加载已保存会话）。
func (r *Ring) Restore(items []*flow.Flow) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := 0; i < r.capacity; i++ {
		r.slots[i] = nil
	}
	r.start = 0
	r.count = 0
	r.byID = make(map[string]int, r.capacity)
	r.nextSeq = 0
	r.bytes = 0
	r.evicted = 0

	for _, f := range items {
		if f == nil {
			continue
		}
		if f.ID == "" {
			f.ID = ulid.Make().String()
		}
		if f.StartedAt.IsZero() {
			f.StartedAt = time.Now()
		}
		if f.Tags == nil {
			f.Tags = []string{}
		}
		f.SessionID = r.sessionID
		r.nextSeq++
		f.Seq = r.nextSeq

		var idx int
		if r.count == r.capacity {
			idx = r.start
			old := r.slots[idx]
			if old != nil {
				delete(r.byID, old.ID)
				r.bytes -= old.ReqSize + old.RespSize
				r.evicted++
			}
			r.slots[idx] = f
			r.start = (r.start + 1) % r.capacity
		} else {
			idx = (r.start + r.count) % r.capacity
			r.slots[idx] = f
			r.count++
		}
		r.byID[f.ID] = idx
		r.bytes += f.ReqSize + f.RespSize
	}
	return r.count
}

func (r *Ring) Get(id string) (*flow.Flow, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idx, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	f := r.slots[idx]
	if f == nil || f.ID != id {
		return nil, false
	}
	return f.Clone(), true
}

func (r *Ring) Patch(id string, patch flow.Patch) (*flow.Flow, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	idx, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	f := r.slots[idx]
	if f == nil || f.ID != id {
		return nil, false
	}
	if patch.Note != nil {
		f.Note = *patch.Note
	}
	if patch.Tags != nil {
		f.Tags = make([]string, len(*patch.Tags))
		copy(f.Tags, *patch.Tags)
	}
	if patch.Pinned != nil {
		f.Pinned = *patch.Pinned
	}
	return f.Clone(), true
}

func (r *Ring) Clear() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := r.count
	for i := 0; i < r.capacity; i++ {
		r.slots[i] = nil
	}
	r.start = 0
	r.count = 0
	r.byID = make(map[string]int, r.capacity)
	r.nextSeq = 0
	r.bytes = 0
	r.evicted = 0
	return n
}

// List 返回按 seq 排序的结果。cursor 为上一页最后一条的 seq（不包含）。
// match 为 nil 时返回全部。
func (r *Ring) List(match flow.Predicate, cursor int64, limit int, desc bool) ([]*flow.Flow, bool, int) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.count == 0 {
		return nil, false, 0
	}

	out := make([]*flow.Flow, 0, limit)
	total := 0
	hasMore := false

	visit := func(f *flow.Flow) bool {
		if f == nil {
			return true
		}
		if match != nil && !match(f) {
			return true
		}
		total++
		if cursor > 0 {
			if desc && f.Seq >= cursor {
				return true
			}
			if !desc && f.Seq <= cursor {
				return true
			}
		}
		if len(out) >= limit {
			hasMore = true
			return true
		}
		out = append(out, f.Clone())
		return true
	}

	if desc {
		for i := r.count - 1; i >= 0; i-- {
			idx := (r.start + i) % r.capacity
			visit(r.slots[idx])
		}
	} else {
		for i := 0; i < r.count; i++ {
			idx := (r.start + i) % r.capacity
			visit(r.slots[idx])
		}
	}

	return out, hasMore, total
}

func (r *Ring) All() []*flow.Flow {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*flow.Flow, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := (r.start + i) % r.capacity
		if f := r.slots[idx]; f != nil {
			out = append(out, f.Clone())
		}
	}
	return out
}

func (r *Ring) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return Stats{
		Count:    r.count,
		Capacity: r.capacity,
		Bytes:    r.bytes,
		Evicted:  r.evicted,
	}
}

func (r *Ring) SessionID() string {
	return r.sessionID
}
