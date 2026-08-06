package network

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDNSResponseToDNSAnswer_EmptyResponse(t *testing.T) {
	msg := new(dns.Msg)
	result := dnsResponseToDNSAnswer(msg)
	assert.NotNil(t, result)
	assert.Empty(t, result.Addresses)
}

func TestDNSResponseToDNSAnswer_ARecord(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = append(msg.Answer, &dns.A{A: net.ParseIP("10.0.0.1"), Hdr: dns.RR_Header{Rrtype: dns.TypeA}})
	result := dnsResponseToDNSAnswer(msg)
	assert.NotNil(t, result)
	assert.Len(t, result.Addresses, 1)
	assert.Equal(t, "10.0.0.1", result.Addresses[0].String())
}
