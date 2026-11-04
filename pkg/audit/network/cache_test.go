package network

import (
	"fmt"
	"net"
	"sync"
	"testing"

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
				cache.Store(addr, "concurrent.example.")
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
