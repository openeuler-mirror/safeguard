package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSCacheConcurrentAccess(t *testing.T) {
	cache := newDNSCache()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			addr := fmt.Sprintf("192.0.2.%d", i)
			for j := 0; j < 100; j++ {
				cache.Store(addr, "concurrent.example.", 60)
				_ = cache.Lookup(addr)
				_ = cache.Len()
			}
		}(i)
	}
	workers.Wait()
	require.Equal(t, 8, cache.Len())
	require.Equal(t, "concurrent.example.", cache.Lookup("192.0.2.0"))
}

func TestDNSCacheOwner(t *testing.T) {
	first := Manager{dnsCache: newDNSCache()}
	second := Manager{dnsCache: newDNSCache()}
	answer := &DNSAnswer{Addresses: []net.IP{net.IPv4(192, 0, 2, 1)}, TTL: 60}
	updateDNSCache("first.example.", answer, first.dnsCache)
	updateDNSCache("second.example.", answer, second.dnsCache)
	body := detectEventIPv4{DstIP: [4]byte{192, 0, 2, 1}}
	require.Equal(t, "first.example.", newAuditLog(eventHeader{}, body, first.dnsCache).Domain)
	require.Equal(t, "second.example.", newAuditLog(eventHeader{}, body, second.dnsCache).Domain)
	require.Empty(t, newAuditLog(eventHeader{}, body, nil).Domain)
}

func TestDNSCacheExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	cache := newDNSCache()
	cache.now = func() time.Time { return now }
	cache.Store("192.0.2.1", "expires.example.", 2)
	now = now.Add(time.Second)
	require.Equal(t, "expires.example.", cache.Lookup("192.0.2.1"))
	now = now.Add(time.Second)
	require.Empty(t, cache.Lookup("192.0.2.1"))
	require.Zero(t, cache.Len())
	cache.Store("192.0.2.1", "zero.example.", 0)
	require.Empty(t, cache.Lookup("192.0.2.1"))
}

func TestDNSCacheBound(t *testing.T) {
	cache := newDNSCache()
	cache.limit = 2
	cache.Store("192.0.2.2", "two.example.", 60)
	cache.Store("192.0.2.1", "one.example.", 60)
	cache.Store("192.0.2.2", "updated.example.", 60)
	require.Equal(t, 2, cache.Len())
	require.NotEmpty(t, cache.Lookup("192.0.2.1"))
	cache.Store("192.0.2.3", "three.example.", 60)
	require.Equal(t, 2, cache.Len())
	require.Empty(t, cache.Lookup("192.0.2.1"))
	require.Equal(t, "two.example.,updated.example.", cache.Lookup("192.0.2.2"))
}

func TestDNSCacheReverse(t *testing.T) {
	now := time.Unix(0, 0)
	cache := newDNSCache()
	cache.now = func() time.Time { return now }
	cache.Store("192.0.2.1", "b.example.", 5)
	cache.Store("192.0.2.1", "a.example.", 1)
	require.Equal(t, "a.example.,b.example.", cache.Lookup("192.0.2.1"))
	now = now.Add(time.Second)
	require.Equal(t, "b.example.", cache.Lookup("192.0.2.1"))
	for i := 0; i < 100; i++ {
		cache.Store("192.0.2.2", fmt.Sprintf("%03d.example.", i), 60)
	}
	require.Len(t, strings.Split(cache.Lookup("192.0.2.2"), ","), 16)
	now = now.Add(60 * time.Second)
	cache.Store("192.0.2.2", "fresh.example.", 60)
	require.Equal(t, "fresh.example.", cache.Lookup("192.0.2.2"))
}

func TestDNSCacheReplace(t *testing.T) {
	cache := newDNSCache()
	cache.Store("192.0.2.1", "shared.example.", 60)
	cache.Store("2001:db8::1", "rotate.example.", 60)
	cache.Replace("rotate.example.", dns.TypeA, []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)}, 60)
	cache.Replace("rotate.example.", dns.TypeA, []net.IP{net.IPv4(192, 0, 2, 3)}, 60)
	require.Equal(t, "shared.example.", cache.Lookup("192.0.2.1"))
	require.Empty(t, cache.Lookup("192.0.2.2"))
	require.Equal(t, "rotate.example.", cache.Lookup("192.0.2.3"))
	require.Equal(t, "rotate.example.", cache.Lookup("2001:db8::1"))
	cache.Replace("rotate.example.", dns.TypeAAAA, nil, 0)
	require.Empty(t, cache.Lookup("2001:db8::1"))
	require.Equal(t, "rotate.example.", cache.Lookup("192.0.2.3"))
	cache.Replace("rotate.example.", dns.TypeMX, nil, 0)
	require.Equal(t, "rotate.example.", cache.Lookup("192.0.2.3"))
	cache.Replace("rotate.example.", 0, nil, 0)
	require.Empty(t, cache.Lookup("192.0.2.3"))
	require.Equal(t, "shared.example.", cache.Lookup("192.0.2.1"))
}

func TestDNSCacheCanonicalName(t *testing.T) {
	cache := newDNSCache()
	cache.Store("192.0.2.1", "WWW.Example.", 60)
	cache.Store("192.0.2.1", `\087ww.example.`, 60)
	require.Equal(t, "www.example.", cache.Lookup("192.0.2.1"))
	cache.Replace("wWw.Example.", dns.TypeA, []net.IP{net.IPv4(192, 0, 2, 2)}, 60)
	require.Empty(t, cache.Lookup("192.0.2.1"))
	require.Equal(t, "www.example.", cache.Lookup("192.0.2.2"))
	cache.Store("192.0.2.3", "Ä.Example.", 60)
	cache.Store("192.0.2.3", "ä.Example.", 60)
	require.Len(t, strings.Split(cache.Lookup("192.0.2.3"), ","), 2)
}

func TestDNSCacheExpiredEviction(t *testing.T) {
	now := time.Unix(0, 0)
	cache := newDNSCache()
	cache.now = func() time.Time { return now }
	cache.limit = 2
	cache.Store("192.0.2.1", "live.example.", 60)
	cache.Store("192.0.2.2", "expired.example.", 1)
	now = now.Add(time.Second)
	cache.Store("192.0.2.3", "new.example.", 60)
	require.Equal(t, "live.example.", cache.Lookup("192.0.2.1"))
	require.Empty(t, cache.Lookup("192.0.2.2"))
	require.Equal(t, "new.example.", cache.Lookup("192.0.2.3"))
	require.Equal(t, 2, cache.Len())
}
