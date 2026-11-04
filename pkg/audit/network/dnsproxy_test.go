package network

import (
	"culinux/pkg/config"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
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

func TestDNSProxyFlags(t *testing.T) {
	for _, rd := range []bool{false, true} {
		forwarded := make(chan struct{}, 1)
		resolver := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			forwarded <- struct{}{}
			response := new(dns.Msg)
			response.SetReply(q)
			w.WriteMsg(response)
		})
		proxy := &DNSProxy{client: resolver.client, dnsConfig: resolver.config, manager: &Manager{config: config.DefaultConfig(), dnsCache: newDNSCache()}}
		request := new(dns.Msg)
		request.SetQuestion("flags.example.", dns.TypeA)
		request.RecursionDesired = rd
		writer := new(proxyCapture)
		proxy.ServeDNS(writer, request)
		select {
		case <-forwarded:
		default:
			t.Fatal("request was not forwarded")
		}
		require.False(t, writer.msg.Authoritative)
		require.True(t, writer.msg.RecursionAvailable)
		require.Equal(t, rd, writer.msg.RecursionDesired)
		require.Equal(t, request.Question, writer.msg.Question)
	}
}

func TestDNSProxyRcode(t *testing.T) {
	for _, code := range []int{dns.RcodeNameError, dns.RcodeServerFailure, -1} {
		code := code
		resolver := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			if code < 0 {
				return
			}
			response := new(dns.Msg)
			response.SetRcode(q, code)
			w.WriteMsg(response)
		})
		resolver.client.Timeout = 10 * time.Millisecond
		proxy := &DNSProxy{client: resolver.client, dnsConfig: resolver.config, manager: &Manager{config: config.DefaultConfig(), dnsCache: newDNSCache()}}
		request := new(dns.Msg)
		request.SetQuestion("rcode.example.", dns.TypeA)
		writer := new(proxyCapture)
		proxy.ServeDNS(writer, request)
		expected := code
		if code < 0 {
			expected = dns.RcodeServerFailure
		}
		require.Equal(t, expected, writer.msg.Rcode)
		require.Empty(t, writer.msg.Answer)
	}
}
