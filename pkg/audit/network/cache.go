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
	limit   int
	now     func() time.Time
	mu      sync.RWMutex
	entries map[string]dnsNameEntry
}

func newDNSCache() *dnsNameCache {
	return &dnsNameCache{entries: make(map[string]dnsNameEntry), now: time.Now, limit: 4096}
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
	if c.limit <= 0 {
		return
	}
	if _, exists := c.entries[addr]; !exists && len(c.entries) >= c.limit {
		victim := ""
		for candidate := range c.entries {
			if victim == "" || candidate < victim {
				victim = candidate
			}
		}
		delete(c.entries, victim)
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
