package network

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type dnsNameEntry map[string]time.Time

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
	names := c.entries[addr]
	if names == nil {
		names = make(dnsNameEntry)
		c.entries[addr] = names
	}
	for name, expiry := range names {
		if !c.now().Before(expiry) {
			delete(names, name)
		}
	}
	if _, exists := names[domain]; !exists && len(names) >= 16 {
		return
	}
	names[domain] = c.now().Add(time.Duration(ttl) * time.Second)
}

func (c *dnsNameCache) Lookup(addr string) string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var names []string
	for domain, expiry := range c.entries[addr] {
		if c.now().Before(expiry) {
			names = append(names, domain)
		} else {
			delete(c.entries[addr], domain)
		}
	}
	if len(c.entries[addr]) == 0 {
		delete(c.entries, addr)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func (c *dnsNameCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
