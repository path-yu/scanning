package capture

import (
	"sort"
	"sync"
	"time"
)

type DNSMap struct {
	mu      sync.RWMutex
	byIP    map[string][]DNSEntry
	maxKeys int
}

func NewDNSMap() *DNSMap {
	return &DNSMap{byIP: make(map[string][]DNSEntry), maxKeys: 20000}
}

func (m *DNSMap) Add(domain, ip string, ttl int, now time.Time) {
	if domain == "" || ip == "" {
		return
	}
	if ttl <= 0 {
		ttl = 300
	}
	if ttl > 86400 {
		ttl = 86400
	}
	entry := DNSEntry{IP: ip, Domain: domain, TTL: ttl, SeenAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second)}

	m.mu.Lock()
	defer m.mu.Unlock()
	items := m.byIP[ip]
	for i := range items {
		if items[i].Domain == domain {
			items[i] = entry
			m.byIP[ip] = items
			return
		}
	}
	if len(m.byIP) >= m.maxKeys {
		m.pruneLocked(now)
	}
	m.byIP[ip] = append(items, entry)
}

func (m *DNSMap) LookupIP(ip string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	var out []string
	for _, entry := range m.byIP[ip] {
		if entry.ExpiresAt.After(now) {
			out = append(out, entry.Domain)
		}
	}
	sort.Strings(out)
	return out
}

func (m *DNSMap) Entries(limit int) []DNSEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	out := make([]DNSEntry, 0, 64)
	for _, items := range m.byIP {
		for _, entry := range items {
			if entry.ExpiresAt.After(now) {
				out = append(out, entry)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SeenAt.Equal(out[j].SeenAt) {
			return out[i].Domain < out[j].Domain
		}
		return out[i].SeenAt.After(out[j].SeenAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (m *DNSMap) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, items := range m.byIP {
		for _, entry := range items {
			if entry.ExpiresAt.After(now) {
				n++
			}
		}
	}
	return n
}

func (m *DNSMap) Clear() {
	m.mu.Lock()
	m.byIP = make(map[string][]DNSEntry)
	m.mu.Unlock()
}

func (m *DNSMap) pruneLocked(now time.Time) {
	for ip, items := range m.byIP {
		alive := items[:0]
		for _, entry := range items {
			if entry.ExpiresAt.After(now) {
				alive = append(alive, entry)
			}
		}
		if len(alive) == 0 {
			delete(m.byIP, ip)
		} else {
			m.byIP[ip] = alive
		}
	}
}
