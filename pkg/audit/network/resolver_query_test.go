package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func localResolver(t *testing.T, handler dns.HandlerFunc) *DefaultResolver {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: conn, Handler: handler}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	require.NoError(t, err)
	return &DefaultResolver{config: &dns.ClientConfig{Servers: []string{host}, Port: port}, client: new(dns.Client)}
}

func TestResolverIndependentQueries(t *testing.T) {
	r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
		w.WriteMsg(response)
	})
	r.message = new(dns.Msg)
	r.message.SetQuestion("untouched.example.", dns.TypeAAAA)
	r.client.Timeout = time.Second
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			answer, err := r.Resolve(fmt.Sprintf("host%d.example", i), dns.TypeA)
			if err != nil {
				t.Errorf("query %d: %v", i, err)
				return
			}
			if answer.Domain != fmt.Sprintf("host%d.example", i) || len(answer.Addresses) != 1 {
				t.Errorf("mixed answer: %+v", answer)
			}
		}(i)
	}
	workers.Wait()
	require.Equal(t, "untouched.example.", r.message.Question[0].Name)
}

func TestResolverCancellation(t *testing.T) {
	received := make(chan struct{}, 1)
	r := localResolver(t, func(dns.ResponseWriter, *dns.Msg) { received <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := r.ResolveContext(ctx, "silent.example", dns.TypeA); result <- err }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("query did not reach server")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancellation did not interrupt exchange")
	}
}

func TestResolverConfiguredTimeout(t *testing.T) {
	for _, tc := range []struct {
		seconds int
		want    time.Duration
	}{
		{-1, 5 * time.Second}, {0, 5 * time.Second}, {2, 2 * time.Second}, {31, 30 * time.Second}, {int(^uint(0) >> 1), 30 * time.Second},
	} {
		r := &DefaultResolver{config: &dns.ClientConfig{Timeout: tc.seconds}, client: new(dns.Client)}
		require.Equal(t, tc.want, r.queryClient().Timeout)
		require.Zero(t, r.client.Timeout)
		r.client.Timeout = 10 * time.Millisecond
		require.Equal(t, 10*time.Millisecond, r.queryClient().Timeout)
	}
}

func TestResolverResponseIdentity(t *testing.T) {
	for _, kind := range []string{"name", "type", "class", "missing", "opcode", "qr", "case", "escaped"} {
		kind := kind
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(q)
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 0, 2, 1)}}
			switch kind {
			case "name":
				response.Question[0].Name = "other.example."
			case "type":
				response.Question[0].Qtype = dns.TypeAAAA
			case "class":
				response.Question[0].Qclass = dns.ClassCHAOS
			case "missing":
				response.Question = nil
			case "opcode":
				response.Opcode = dns.OpcodeStatus
			case "qr":
				response.Response = false
			case "case":
				response.Question[0].Name = "GOOD.EXAMPLE."
			}
			w.WriteMsg(response)
		})
		host := "good.example"
		if kind == "escaped" {
			host = `escaped\046name.example`
		}
		_, err := r.Resolve(host, dns.TypeA)
		if kind == "case" || kind == "escaped" {
			require.NoError(t, err, kind)
		} else {
			require.Error(t, err, kind)
		}
	}
}

func TestResolverResponseCodes(t *testing.T) {
	for _, code := range []int{dns.RcodeNameError, dns.RcodeServerFailure} {
		code := code
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetRcode(q, code)
			w.WriteMsg(response)
		})
		_, err := r.Resolve("missing.example", dns.TypeA)
		var responseError *DNSResponseError
		require.ErrorAs(t, err, &responseError)
		require.Equal(t, code, responseError.Rcode)
		require.Equal(t, "missing.example", responseError.Domain)
	}
}
