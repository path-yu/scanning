package capture

import (
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

type PacketStats struct {
	Count    int   `json:"count"`
	Capacity int   `json:"capacity"`
	Bytes    int64 `json:"bytes"`
	Evicted  int64 `json:"evicted"`
}

type PacketRing struct {
	mu        sync.RWMutex
	slots     []*Packet
	start     int
	count     int
	capacity  int
	byID      map[string]int
	nextNo    int64
	sessionID string
	bytes     int64
	evicted   int64
}

func NewPacketRing(capacity int, sessionID string) *PacketRing {
	if capacity <= 0 {
		capacity = 20000
	}
	return &PacketRing{
		slots:     make([]*Packet, capacity),
		capacity:  capacity,
		byID:      make(map[string]int, capacity),
		sessionID: sessionID,
	}
}

func (r *PacketRing) Add(p *Packet) *Packet {
	if p == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if p.ID == "" {
		p.ID = ulid.Make().String()
	}
	if p.Timestamp.IsZero() {
		p.Timestamp = time.Now()
	}
	p.SessionID = r.sessionID
	r.nextNo++
	p.No = r.nextNo

	var idx int
	if r.count == r.capacity {
		idx = r.start
		old := r.slots[idx]
		if old != nil {
			delete(r.byID, old.ID)
			r.bytes -= int64(len(old.Raw))
			r.evicted++
		}
		r.slots[idx] = p
		r.start = (r.start + 1) % r.capacity
	} else {
		idx = (r.start + r.count) % r.capacity
		r.slots[idx] = p
		r.count++
	}
	r.byID[p.ID] = idx
	r.bytes += int64(len(p.Raw))
	return p.Clone()
}

func (r *PacketRing) Get(id string) (*Packet, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	idx, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	p := r.slots[idx]
	if p == nil || p.ID != id {
		return nil, false
	}
	return p.Clone(), true
}

// List 按报文序号返回摘要。cursor 为上一页最后一条的 No（不包含）。
func (r *PacketRing) List(cursor int64, limit int, desc bool, match func(*Packet) bool) ([]PacketSummary, bool, int) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]PacketSummary, 0, limit)
	total := 0
	hasMore := false

	visit := func(p *Packet) {
		if p == nil {
			return
		}
		if match != nil && !match(p) {
			return
		}
		total++
		if cursor > 0 {
			if desc && p.No >= cursor {
				return
			}
			if !desc && p.No <= cursor {
				return
			}
		}
		if len(out) >= limit {
			hasMore = true
			return
		}
		out = append(out, p.SummaryInfo())
	}

	if desc {
		for i := r.count - 1; i >= 0; i-- {
			visit(r.slots[(r.start+i)%r.capacity])
		}
	} else {
		for i := 0; i < r.count; i++ {
			visit(r.slots[(r.start+i)%r.capacity])
		}
	}
	return out, hasMore, total
}

// All 返回按序号升序的报文副本，用于 PCAP 导出。
func (r *PacketRing) All() []*Packet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Packet, 0, r.count)
	for i := 0; i < r.count; i++ {
		if p := r.slots[(r.start+i)%r.capacity]; p != nil {
			out = append(out, p.Clone())
		}
	}
	return out
}

// AttachFlow 把双向五元组上的报文关联到 HTTP Flow。
func (r *PacketRing) AttachFlow(srcIP string, srcPort int, dstIP string, dstPort int, flowID string) int {
	if flowID == "" {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := 0
	for i := 0; i < r.count; i++ {
		p := r.slots[(r.start+i)%r.capacity]
		if p == nil || p.FlowID == flowID {
			continue
		}
		if (p.SrcIP == srcIP && p.SrcPort == srcPort && p.DstIP == dstIP && p.DstPort == dstPort) ||
			(p.SrcIP == dstIP && p.SrcPort == dstPort && p.DstIP == srcIP && p.DstPort == srcPort) {
			p.FlowID = flowID
			changed++
		}
	}
	return changed
}

func (r *PacketRing) Clear() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.count
	for i := 0; i < r.capacity; i++ {
		r.slots[i] = nil
	}
	r.start = 0
	r.count = 0
	r.byID = make(map[string]int, r.capacity)
	r.nextNo = 0
	r.bytes = 0
	r.evicted = 0
	return n
}

func (r *PacketRing) Stats() PacketStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return PacketStats{Count: r.count, Capacity: r.capacity, Bytes: r.bytes, Evicted: r.evicted}
}

func (r *PacketRing) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}
