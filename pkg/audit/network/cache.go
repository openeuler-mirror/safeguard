package network

import "sync"

type dnsNameCache struct {
	mu      sync.RWMutex
	entries map[string]string
}

func newDNSCache() *dnsNameCache { return &dnsNameCache{entries: make(map[string]string)} }

func (c *dnsNameCache) Store(addr, domain string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[addr] = domain
}

func (c *dnsNameCache) Lookup(addr string) string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[addr]
}

func (c *dnsNameCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
