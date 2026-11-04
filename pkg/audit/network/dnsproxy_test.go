package network

import (
	"bytes"
	"culinux/pkg/config"
	log "culinux/pkg/log"
	"errors"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"net"
	"strings"
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

func TestDNSProxyFallback(t *testing.T) {
	forwarded := make(chan struct{}, 1)
	resolver := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
		forwarded <- struct{}{}
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 42)}}
		w.WriteMsg(response)
	})
	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.2", resolver.config.Port))
	require.NoError(t, err)
	silent := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})}
	go silent.ActivateAndServe()
	t.Cleanup(func() { silent.Shutdown() })
	resolver.config.Servers = []string{"127.0.0.2", "127.0.0.1"}
	resolver.client.Timeout = 25 * time.Millisecond
	proxy := &DNSProxy{client: resolver.client, dnsConfig: resolver.config, manager: &Manager{config: config.DefaultConfig(), dnsCache: newDNSCache()}}
	request := new(dns.Msg)
	request.SetQuestion("fallback.example.", dns.TypeA)
	writer := new(proxyCapture)
	proxy.ServeDNS(writer, request)
	select {
	case <-forwarded:
	default:
		t.Fatal("second upstream was not queried")
	}
	require.Equal(t, dns.RcodeSuccess, writer.msg.Rcode)
	require.Len(t, writer.msg.Answer, 1)
	require.Equal(t, "fallback.example.", proxy.manager.dnsCache.Lookup("192.0.2.42"))
}

type failingProxyWriter struct{ proxyCapture }

func (w *failingProxyWriter) WriteMsg(m *dns.Msg) error {
	w.proxyCapture.WriteMsg(m)
	return errors.New("injected response write failure")
}

func TestDNSProxyWriteError(t *testing.T) {
	var logs bytes.Buffer
	old := log.Logger.Logger.Out
	log.Logger.Logger.SetOutput(&logs)
	t.Cleanup(func() { log.Logger.Logger.SetOutput(old) })
	resolver := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		w.WriteMsg(response)
	})
	proxy := &DNSProxy{client: resolver.client, dnsConfig: resolver.config, manager: &Manager{config: config.DefaultConfig(), dnsCache: newDNSCache()}}
	for _, opcode := range []int{dns.OpcodeUpdate, dns.OpcodeQuery} {
		q := new(dns.Msg)
		q.SetQuestion("write.example.", dns.TypeA)
		q.Opcode = opcode
		writer := new(failingProxyWriter)
		proxy.ServeDNS(writer, q)
		require.NotNil(t, writer.msg)
	}
	require.Equal(t, 2, strings.Count(logs.String(), "injected response write failure"))
}

func TestDNSProxyRelevantAddresses(t *testing.T) {
	resolver := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 5}, Target: "alias.example."},
			&dns.A{Hdr: dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)},
			&dns.A{Hdr: dns.RR_Header{Name: "unrelated.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 2)},
			&dns.A{Hdr: dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeA, Class: dns.ClassCHAOS, Ttl: 60}, A: net.IPv4(192, 0, 2, 3)},
		}
		w.WriteMsg(response)
	})
	cache := newDNSCache()
	now := time.Unix(0, 0)
	cache.now = func() time.Time { return now }
	proxy := &DNSProxy{client: resolver.client, dnsConfig: resolver.config, manager: &Manager{config: config.DefaultConfig(), dnsCache: cache}}
	request := new(dns.Msg)
	request.SetQuestion("target.example.", dns.TypeA)
	writer := new(proxyCapture)
	proxy.ServeDNS(writer, request)
	require.Len(t, writer.msg.Answer, 4)
	require.Equal(t, "target.example.", cache.Lookup("192.0.2.1"))
	require.Empty(t, cache.Lookup("192.0.2.2"))
	require.Empty(t, cache.Lookup("192.0.2.3"))
	now = now.Add(5 * time.Second)
	require.Empty(t, cache.Lookup("192.0.2.1"))
}

func TestDNSProxyRelevantAddressesAliasCycle(t *testing.T) {
	resolver := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: q.Question[0].Name}}
		w.WriteMsg(response)
	})
	cache := newDNSCache()
	proxy := &DNSProxy{client: resolver.client, dnsConfig: resolver.config, manager: &Manager{config: config.DefaultConfig(), dnsCache: cache}}
	request := new(dns.Msg)
	request.SetQuestion("cycle.example.", dns.TypeA)
	writer := new(proxyCapture)
	proxy.ServeDNS(writer, request)
	require.Equal(t, dns.RcodeServerFailure, writer.msg.Rcode)
	require.Zero(t, cache.Len())
}
