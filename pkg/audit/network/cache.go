package network

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
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
	domain = canonicalCacheName(domain)
	if domain == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeLocked(addr, domain, ttl)
}

func (c *dnsNameCache) storeLocked(addr, domain string, ttl uint32) {
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

// Replace atomically updates one domain's reverse references, preserving peers.
func (c *dnsNameCache) Replace(domain string, qtype uint16, addresses []net.IP, ttl uint32) {
	if c == nil || qtype != 0 && qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return
	}
	domain = canonicalCacheName(domain)
	if domain == "" {
		return
	}
	wanted := make(map[string]bool, len(addresses))
	for _, ip := range addresses {
		wanted[ip.String()] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for addr, names := range c.entries {
		if qtype == dns.TypeA && net.ParseIP(addr).To4() == nil || qtype == dns.TypeAAAA && net.ParseIP(addr).To4() != nil {
			continue
		}
		if !wanted[addr] || ttl == 0 {
			delete(names, domain)
		}
		if len(names) == 0 {
			delete(c.entries, addr)
		}
	}
	keys := make([]string, 0, len(wanted))
	for addr := range wanted {
		keys = append(keys, addr)
	}
	sort.Strings(keys)
	for _, addr := range keys {
		c.storeLocked(addr, domain, ttl)
	}
}

func canonicalCacheName(name string) string {
	if name == "" {
		return ""
	}
	var wire [255]byte
	n, err := dns.PackDomainName(dns.Fqdn(name), wire[:], 0, nil, false)
	if err != nil {
		return ""
	}
	for i := 0; i < n; i++ {
		if wire[i] >= 'A' && wire[i] <= 'Z' {
			wire[i] += 'a' - 'A'
		}
	}
	result, _, err := dns.UnpackDomainName(wire[:n], 0)
	if err != nil {
		return ""
	}
	return result
}
