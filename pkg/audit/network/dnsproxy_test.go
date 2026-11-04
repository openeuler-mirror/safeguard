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

type proxyCapture struct{ msg *dns.Msg }

func (w *proxyCapture) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (w *proxyCapture) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (w *proxyCapture) WriteMsg(m *dns.Msg) error { w.msg = m.Copy(); return nil }
func (*proxyCapture) Write([]byte) (int, error)   { return 0, nil }
func (*proxyCapture) Close() error                { return nil }
func (*proxyCapture) TsigStatus() error           { return nil }
func (*proxyCapture) TsigTimersOnly(bool)         {}
func (*proxyCapture) Hijack()                     {}

func TestDNSProxyQuestion(t *testing.T) {
	for _, count := range []int{0, 2} {
		request := new(dns.Msg)
		for i := 0; i < count; i++ {
			request.Question = append(request.Question, dns.Question{Name: "invalid.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		}
		writer := new(proxyCapture)
		require.NotPanics(t, func() { new(DNSProxy).ServeDNS(writer, request) })
		require.NotNil(t, writer.msg)
		require.Equal(t, dns.RcodeFormatError, writer.msg.Rcode)
	}
}

func TestDNSProxyOpcode(t *testing.T) {
	for _, code := range []int{dns.OpcodeUpdate, dns.OpcodeStatus, dns.OpcodeNotify} {
		request := new(dns.Msg)
		request.SetQuestion("opcode.example.", dns.TypeA)
		request.Opcode = code
		writer := new(proxyCapture)
		require.NotPanics(t, func() { new(DNSProxy).ServeDNS(writer, request) })
		require.Equal(t, dns.RcodeNotImplemented, writer.msg.Rcode)
	}
}
