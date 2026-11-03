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
