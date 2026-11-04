package network

import "sync"

type dnsNameCache struct {
	mu      sync.RWMutex
	entries map[string]string
}

func newDNSCache() *dnsNameCache { return &dnsNameCache{entries: make(map[string]string)} }

func (c *dnsNameCache) Store(addr, domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[addr] = domain
}

func (c *dnsNameCache) Lookup(addr string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[addr]
}

func (c *dnsNameCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
