package network

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"testing"
	"time"

	"culinux/pkg/config"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type refreshFailure struct{ err error }

func (r refreshFailure) Resolve(string, uint16) (*DNSAnswer, error) { return nil, r.err }

func TestDNSRefreshErrors(t *testing.T) {
	cause := errors.New("upstream unavailable")
	mgr := Manager{dnsResolver: refreshFailure{cause}}
	for _, run := range []func(string, uint16) (uint32, error){mgr.resolveAndUpdateAllowedFQDNList, mgr.resolveAndUpdateDeniedFQDNList} {
		for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
			_, err := run("retry.example.", kind)
			require.ErrorIs(t, err, cause)
		}
	}
}

func TestDNSRefreshBackoff(t *testing.T) {
	var retry refreshRetry
	cause := errors.New("temporary")
	for _, seconds := range []int{5, 10, 20, 40, 60, 60, 60} {
		require.Equal(t, time.Duration(seconds)*time.Second, retry.base(1, cause))
	}
	require.Equal(t, 2*time.Second, retry.base(2, nil))
	require.Equal(t, 5*time.Second, retry.base(1, cause))
	require.Equal(t, time.Second, retry.base(0, nil))
}

type contextualRefresh struct {
	refreshFailure
	seen context.Context
}

func (r *contextualRefresh) ResolveContext(ctx context.Context, _ string, _ uint16) (*DNSAnswer, error) {
	r.seen = ctx
	return nil, ctx.Err()
}

func TestDNSRefreshContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := &contextualRefresh{refreshFailure: refreshFailure{errors.New("legacy call")}}
	mgr := Manager{dnsResolver: resolver, dnsContext: ctx}
	_, err := mgr.ResolveAddressv4("canceled.example")
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, ctx, resolver.seen)
	_, err = mgr.ResolveAddressv6("canceled.example")
	require.ErrorIs(t, err, context.Canceled)
	legacy := errors.New("legacy resolver remains supported")
	mgr.dnsResolver = refreshFailure{legacy}
	mgr.dnsContext = context.Background()
	_, err = mgr.ResolveAddressv4("legacy.example")
	require.ErrorIs(t, err, legacy)
}

func TestDNSRefreshStop(t *testing.T) {
	for _, stop := range []func(*Manager){(*Manager).Stop, (*Manager).Close} {
		started := make(chan struct{}, 4)
		resolver := localResolver(t, func(dns.ResponseWriter, *dns.Msg) { started <- struct{}{} })
		cfg := config.DefaultConfig()
		cfg.Domain.Allow = []string{"stop.example."}
		mgr := Manager{config: cfg, dnsResolver: resolver, dnsContext: context.Background()}
		mgr.AsyncResolve()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("refresh did not start")
		}
		stopped := make(chan struct{})
		go func(stop func(*Manager)) {
			stop(&mgr)
			close(stopped)
		}(stop)
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("refresh did not stop")
		}
		require.ErrorIs(t, mgr.dnsContext.Err(), context.Canceled)
		mgr.AsyncResolve() // A stopped manager cannot restart refresh workers.
	}
}

func TestDNSRefreshJitter(t *testing.T) {
	left := refreshRetry{rng: rand.New(rand.NewSource(7))}
	right := refreshRetry{rng: rand.New(rand.NewSource(7))}
	seen := make(map[time.Duration]bool)
	for i := 0; i < 10; i++ {
		delay := left.next(50, nil)
		seen[delay] = true
		require.Equal(t, delay, right.next(50, nil))
		require.GreaterOrEqual(t, delay, 40*time.Second)
		require.LessOrEqual(t, delay, 50*time.Second)
	}
	require.Greater(t, len(seen), 1)
	require.Equal(t, time.Second, left.next(0, nil))
	delay := left.next(1, errors.New("temporary"))
	require.GreaterOrEqual(t, delay, 4*time.Second)
	require.LessOrEqual(t, delay, 5*time.Second)
}

func TestDNSUpdateCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mgr := Manager{dnsContext: ctx}
	answer := &DNSAnswer{Domain: "canceled.example.", Addresses: []net.IP{net.IPv4(192, 0, 2, 1)}}
	for _, update := range []func(*DNSAnswer) error{mgr.updateAllowedFQDNist, mgr.updateDeniedFQDNList} {
		require.NotPanics(t, func() { require.ErrorIs(t, update(answer), context.Canceled) })
	}
}

func TestDNSRefreshNilAnswer(t *testing.T) {
	for _, resolver := range []DNSResolver{refreshFailure{}, &contextualRefresh{}} {
		mgr := Manager{dnsResolver: resolver, dnsContext: context.Background()}
		for _, run := range []func(string, uint16) (uint32, error){mgr.resolveAndUpdateAllowedFQDNList, mgr.resolveAndUpdateDeniedFQDNList} {
			for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
				require.NotPanics(t, func() { _, err := run("missing.example.", kind); require.ErrorContains(t, err, "nil answer") })
			}
		}
	}
}

type emptyAnswerResolver struct{}

func (emptyAnswerResolver) Resolve(name string, _ uint16) (*DNSAnswer, error) {
	return &DNSAnswer{Domain: name, TTL: 60}, nil
}

func TestDNSRefreshEmptyAnswer(t *testing.T) {
	mgr := Manager{dnsResolver: emptyAnswerResolver{}, dnsContext: context.Background()}
	for _, run := range []func(string, uint16) (uint32, error){mgr.resolveAndUpdateAllowedFQDNList, mgr.resolveAndUpdateDeniedFQDNList} {
		for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
			ttl, err := run("empty.example.", kind)
			require.ErrorIs(t, err, ErrDNSNoData)
			require.Equal(t, uint32(5), ttl)
		}
	}
}

type countingLegacyResolver struct {
	calls int
	err   error
}

func (r *countingLegacyResolver) Resolve(string, uint16) (*DNSAnswer, error) {
	r.calls++
	return nil, r.err
}

func TestDNSLegacyResolverCanceled(t *testing.T) {
	cause := errors.New("legacy invoked")
	resolver := &countingLegacyResolver{err: cause}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mgr := Manager{dnsResolver: resolver, dnsContext: ctx}
	_, err := mgr.ResolveAddressv4("test.example")
	require.ErrorIs(t, err, context.Canceled)
	_, err = mgr.ResolveAddressv6("test.example")
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, resolver.calls)
	mgr.dnsContext = context.Background()
	_, err = mgr.ResolveAddressv4("test.example")
	require.ErrorIs(t, err, cause)
	require.Equal(t, 1, resolver.calls)
}
