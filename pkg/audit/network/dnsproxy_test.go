package network

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestDNSZeroTTLCache(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		dnsCache = newDNSCache()
		a := &dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA, Ttl: 0}, A: net.IPv4(192, 0, 2, 1)}
		aaaa := &dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")}
		response := &dns.Msg{Answer: []dns.RR{a, aaaa}}
		if reverse {
			response.Answer[0], response.Answer[1] = response.Answer[1], response.Answer[0]
		}
		answer := dnsResponseToDNSAnswer(response)
		require.Zero(t, answer.TTL)
		require.Len(t, answer.Addresses, 2)
		updateDNSCache("zero.example.", answer)
		require.Zero(t, dnsCache.Len())
		a.Hdr.Ttl = 60
		answer = dnsResponseToDNSAnswer(response)
		require.Equal(t, uint32(60), answer.TTL)
		updateDNSCache("positive.example.", answer)
		require.Equal(t, "positive.example.", dnsCache.Lookup("192.0.2.1"))
	}
}
