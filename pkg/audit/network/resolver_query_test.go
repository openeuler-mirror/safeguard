package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
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

func TestResolverNoDataClassification(t *testing.T) {
	for _, unrelated := range []bool{false, true} {
		unrelated := unrelated
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(q)
			if unrelated {
				response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
			}
			w.WriteMsg(response)
		})
		answer, err := r.Resolve("empty.example", dns.TypeA)
		require.Nil(t, answer)
		require.ErrorIs(t, err, ErrDNSNoData)
	}
}

func TestResolverFiltersResponseOwners(t *testing.T) {
	r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		for _, text := range []string{
			"unrelated.example. 1 IN A 203.0.113.9",
			"target.example. 60 CH A 203.0.113.8",
			"alias.example. 60 IN CNAME target.example.",
			"target.example. 60 IN A 192.0.2.1",
		} {
			rr, err := dns.NewRR(text)
			if err != nil {
				t.Error(err)
				return
			}
			response.Answer = append(response.Answer, rr)
		}
		w.WriteMsg(response)
	})
	answer, err := r.Resolve("alias.example", dns.TypeA)
	require.NoError(t, err)
	require.Equal(t, "alias.example", answer.Domain)
	require.Equal(t, []net.IP{net.ParseIP("192.0.2.1").To4()}, answer.Addresses)
}

func TestResolverAliasBounds(t *testing.T) {
	for _, count := range []int{2, 16, 17} {
		count := count
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(q)
			for i := 0; i < count; i++ {
				target := fmt.Sprintf("n%d.example.", i+1)
				if count == 2 && i == 1 {
					target = "N0.EXAMPLE."
				}
				rr, err := dns.NewRR(fmt.Sprintf("n%d.example. 60 IN CNAME %s", i, target))
				if err != nil {
					t.Error(err)
					return
				}
				response.Answer = append(response.Answer, rr)
			}
			rr, _ := dns.NewRR(fmt.Sprintf("n%d.example. 60 IN A 192.0.2.1", count))
			response.Answer = append(response.Answer, rr)
			w.WriteMsg(response)
		})
		r.client.UDPSize = 4096
		_, err := r.Resolve("n0.example", dns.TypeA)
		switch count {
		case 2:
			require.ErrorIs(t, err, ErrDNSAliasCycle)
		case 16:
			require.NoError(t, err)
		case 17:
			require.ErrorIs(t, err, ErrDNSAliasLimit)
		}
	}
}

func TestResolverTruncatedTCPRetry(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		truncated := truncated
		var queries int32
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(q)
			response.Truncated = true
			w.WriteMsg(response)
		})
		listener, err := net.Listen("tcp", net.JoinHostPort(r.config.Servers[0], r.config.Port))
		require.NoError(t, err)
		server := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			atomic.AddInt32(&queries, 1)
			response := new(dns.Msg)
			response.SetReply(q)
			response.Truncated = truncated
			rr, _ := dns.NewRR("tcp.example. 60 IN A 192.0.2.1")
			response.Answer = []dns.RR{rr}
			w.WriteMsg(response)
		})}
		go server.ActivateAndServe()
		t.Cleanup(func() { server.Shutdown() })
		answer, err := r.Resolve("tcp.example", dns.TypeA)
		if truncated {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Len(t, answer.Addresses, 1)
		}
		require.Equal(t, int32(1), atomic.LoadInt32(&queries))
	}
}

func TestResolverMinimumRelevantTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl     uint32
		reverse bool
	}{{30, false}, {30, true}, {0, false}, {0, true}} {
		tc := tc
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(q)
			texts := []string{fmt.Sprintf("ttl.example. %d IN CNAME target.example.", tc.ttl), "target.example. 90 IN A 192.0.2.1", "target.example. 60 IN A 192.0.2.2", "unrelated.example. 1 IN A 203.0.113.1"}
			for _, text := range texts {
				rr, _ := dns.NewRR(text)
				response.Answer = append(response.Answer, rr)
			}
			if tc.reverse {
				for i, j := 0, len(response.Answer)-1; i < j; i, j = i+1, j-1 {
					response.Answer[i], response.Answer[j] = response.Answer[j], response.Answer[i]
				}
			}
			w.WriteMsg(response)
		})
		answer, err := r.Resolve("ttl.example", dns.TypeA)
		require.NoError(t, err)
		require.Equal(t, tc.ttl, answer.TTL)
		require.Len(t, answer.Addresses, 2)
	}
	require.Equal(t, time.Second, refreshDelay(0))
	require.Equal(t, 2*time.Second, refreshDelay(2))
}

func TestResolverSharedUpstreamBudget(t *testing.T) {
	var queries int32
	r := localResolver(t, func(dns.ResponseWriter, *dns.Msg) { atomic.AddInt32(&queries, 1) })
	r.config.Servers = []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"}
	r.client.Timeout = 30 * time.Millisecond
	_, err := r.Resolve("silent.example", dns.TypeA)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, int32(1), atomic.LoadInt32(&queries))
}

func TestResolverRetryableResponseCodes(t *testing.T) {
	for _, code := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNameError} {
		code := code
		var queries int32
		r := localResolver(t, func(w dns.ResponseWriter, q *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(q)
			if atomic.AddInt32(&queries, 1) == 1 {
				response.Rcode = code
			} else {
				rr, _ := dns.NewRR("fallback.example. 60 IN A 192.0.2.1")
				response.Answer = []dns.RR{rr}
			}
			w.WriteMsg(response)
		})
		r.config.Servers = []string{"127.0.0.1", "127.0.0.1"}
		_, err := r.Resolve("fallback.example", dns.TypeA)
		if code == dns.RcodeNameError {
			require.Error(t, err)
			require.Equal(t, int32(1), atomic.LoadInt32(&queries))
		} else {
			require.NoError(t, err)
			require.Equal(t, int32(2), atomic.LoadInt32(&queries))
		}
	}
}

func TestResolverEmptyHost(t *testing.T) {
	resolver := &DefaultResolver{config: &dns.ClientConfig{}, client: new(dns.Client)}
	require.NotPanics(t, func() { answer, err := resolver.Resolve("", dns.TypeA); require.Nil(t, answer); require.Error(t, err) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolver.ResolveContext(ctx, "", dns.TypeA)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "", toFqdn(""))
	require.Equal(t, ".", toFqdn("."))
}
