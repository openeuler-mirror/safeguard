package network

import (
	"sync"
	"time"
)

type dnsNameEntry struct {
	domain  string
	expires time.Time
}

type dnsNameCache struct {
	now     func() time.Time
	mu      sync.RWMutex
	entries map[string]dnsNameEntry
}

func newDNSCache() *dnsNameCache {
	return &dnsNameCache{entries: make(map[string]dnsNameEntry), now: time.Now}
}

func (c *dnsNameCache) Store(addr, domain string, ttl uint32) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl == 0 {
		return
	}
	c.entries[addr] = dnsNameEntry{domain: domain, expires: c.now().Add(time.Duration(ttl) * time.Second)}
}

func (c *dnsNameCache) Lookup(addr string) string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[addr]
	if !ok {
		return ""
	}
	if !c.now().Before(entry.expires) {
		delete(c.entries, addr)
		return ""
	}
	return entry.domain
}

func (c *dnsNameCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
