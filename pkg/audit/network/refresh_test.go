package network

import (
	"context"
	"errors"
	"testing"
	"time"

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
		require.Equal(t, time.Duration(seconds)*time.Second, retry.next(1, cause))
	}
	require.Equal(t, 2*time.Second, retry.next(2, nil))
	require.Equal(t, 5*time.Second, retry.next(1, cause))
	require.Equal(t, time.Second, retry.next(0, nil))
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
