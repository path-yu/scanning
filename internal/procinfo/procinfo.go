// Package procinfo 尽力把本机连接归因到发起它的进程。
package procinfo

import (
	"sync"
	"time"
)

type Info struct {
	Name string `json:"name,omitempty"`
	PID  int    `json:"pid,omitempty"`
	Path string `json:"path,omitempty"`
}

type cacheKey struct {
	ip        string
	port      int
	proxyPort int
}

type cacheEntry struct {
	info    Info
	ok      bool
	expires time.Time
}

type Resolver struct {
	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

func New() *Resolver {
	return &Resolver{cache: make(map[cacheKey]cacheEntry)}
}

// Resolve 根据客户端地址与代理端口查找所属进程；失败时返回 false，不影响抓包。
func (r *Resolver) Resolve(clientIP string, clientPort, proxyPort int) (Info, bool) {
	if clientPort <= 0 {
		return Info{}, false
	}
	key := cacheKey{ip: clientIP, port: clientPort, proxyPort: proxyPort}
	now := time.Now()

	r.mu.Lock()
	if entry, ok := r.cache[key]; ok && now.Before(entry.expires) {
		r.mu.Unlock()
		return entry.info, entry.ok
	}
	r.mu.Unlock()

	info, found := lookupProcess(clientIP, clientPort, proxyPort)
	ttl := 2 * time.Second
	if found {
		ttl = 30 * time.Second
	}

	r.mu.Lock()
	if len(r.cache) > 4096 {
		r.cache = make(map[cacheKey]cacheEntry)
	}
	r.cache[key] = cacheEntry{info: info, ok: found, expires: now.Add(ttl)}
	r.mu.Unlock()

	return info, found
}
