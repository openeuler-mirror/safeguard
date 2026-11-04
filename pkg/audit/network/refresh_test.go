package network

import (
	"errors"
	"testing"

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
