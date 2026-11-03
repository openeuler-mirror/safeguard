package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "culinux/pkg/log"

	"github.com/miekg/dns"
)

// DNSResponseError exposes response status without parsing a log message.
type DNSResponseError struct {
	Domain string
	Rcode  int
}

func (e *DNSResponseError) Error() string {
	return fmt.Sprintf("DNS response for %s: code %d", e.Domain, e.Rcode)
}

// ErrDNSNoData denotes a successful DNS reply with no requested addresses.
var ErrDNSNoData = errors.New("DNS response has no requested address records")

type DNSAnswer struct {
	Domain    string
	Addresses []net.IP
	TTL       uint32
}

// dnsCache stores resolved domain-to-IP mappings for periodic name resolution.
var dnsCache map[string]string

// initDNSCache initializes the DNS cache map if it has not been created yet.
func initDNSCache() {
	if dnsCache == nil {
		dnsCache = make(map[string]string)
	}
}

// To FQDN format
// e.g. example.com -> example.com.
// toFqdn converts a domain name to FQDN format by appending a trailing dot.
func toFqdn(domainName string) string {
	if domainName[len(domainName)-1:] == "." {
		return domainName
	}

	return domainName + "."
}

func (r *DefaultResolver) exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	failures := []string{}
	host := ""
	if len(message.Question) > 0 {
		host = message.Question[0].Name
	}

	port := r.config.Port
	if port == "" {
		port = "53"
	}
	for _, server := range r.config.Servers {
		res, err := exchangeDNSContext(ctx, r.queryClient(), message, net.JoinHostPort(server, port))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			log.Debug(fmt.Sprintf("%s query to %s failed. %s", host, server, err))
			failures = append(failures, fmt.Sprintf("%s: %v", server, err))
			continue
		}
		if res == nil || !res.Response || res.Opcode != message.Opcode || len(res.Question) != 1 || !sameDNSQuestion(message.Question[0], res.Question[0]) {
			return nil, errors.New("DNS response identity mismatch")
		}
		return res, nil
	}

	if len(failures) == 0 {
		return nil, errors.New("resolve failed")
	}

	return nil, fmt.Errorf("all dns servers failed for %s: %s", host, strings.Join(failures, "; "))
}

func (r *DefaultResolver) Resolve(host string, recordType uint16) (*DNSAnswer, error) {
	return r.ResolveContext(context.Background(), host, recordType)
}

func (r *DefaultResolver) ResolveContext(ctx context.Context, host string, recordType uint16) (*DNSAnswer, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	message := new(dns.Msg)
	message.SetQuestion(toFqdn(host), recordType)
	message.RecursionDesired = true
	res, err := r.exchange(ctx, message)

	if err != nil {
		log.Error(err)
		return nil, err
	}

	if res.Rcode != dns.RcodeSuccess {
		return nil, &DNSResponseError{Domain: host, Rcode: res.Rcode}
	}

	if len(res.Answer) == 0 {
		return nil, fmt.Errorf("%s type %d: %w", host, recordType, ErrDNSNoData)
	}

	answer := DNSAnswer{Domain: host}
	for _, rr := range res.Answer {
		switch recordType {
		case dns.TypeA:
			if record, ok := rr.(*dns.A); ok {
				answer.Addresses = append(answer.Addresses, record.A)
				answer.TTL = record.Hdr.Ttl
			}
		case dns.TypeAAAA:
			if record, ok := rr.(*dns.AAAA); ok {
				answer.Addresses = append(answer.Addresses, record.AAAA)
				answer.TTL = record.Hdr.Ttl
			}
		}
	}

	if answer.Addresses == nil {
		return nil, fmt.Errorf("%s type %d: %w", host, recordType, ErrDNSNoData)
	}

	return &answer, nil
}

func (mgr *Manager) ResolveAddressv4(domain string) (*DNSAnswer, error) {
	answer, err := mgr.dnsResolver.Resolve(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	return answer, nil
}

func (mgr *Manager) ResolveAddressv6(domain string) (*DNSAnswer, error) {
	answer, err := mgr.dnsResolver.Resolve(domain, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}

	return answer, nil
}

func (mgr *Manager) resolveAndUpdateAllowedFQDNList(domainName string, recordType uint16) (uint32, error) {
	switch recordType {
	case dns.TypeA:
		answer, err := mgr.ResolveAddressv4(domainName)
		if err != nil {
			return 5, nil
		}
		err = mgr.updateAllowedFQDNist(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	case dns.TypeAAAA:
		answer, err := mgr.ResolveAddressv6(domainName)
		if err != nil {
			return 5, nil
		}
		err = mgr.updateAllowedFQDNist(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (AAAA) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	}

	return 5, errors.New("invalid record type")
}

func (mgr *Manager) resolveAndUpdateDeniedFQDNList(domainName string, recordType uint16) (uint32, error) {
	switch recordType {
	case dns.TypeA:
		answer, err := mgr.ResolveAddressv4(domainName)
		if err != nil {
			return 5, nil
		}
		err = mgr.updateDeniedFQDNList(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	case dns.TypeAAAA:
		answer, err := mgr.ResolveAddressv6(domainName)
		if err != nil {
			return 5, nil
		}
		err = mgr.updateDeniedFQDNList(answer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("%s (AAAA) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	}

	return 5, errors.New("invalid record type")
}

func (mgr *Manager) AsyncResolve() {
	for _, allowedDomain := range mgr.config.RestrictedNetworkConfig.Domain.Allow {
		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateAllowedFQDNList(domainName, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(allowedDomain)

		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateAllowedFQDNList(domainName, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(allowedDomain)
	}

	for _, deniedDomain := range mgr.config.RestrictedNetworkConfig.Domain.Deny {
		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateDeniedFQDNList(domainName, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(deniedDomain)

		go func(domainName string) {
			for {
				ttl, err := mgr.resolveAndUpdateDeniedFQDNList(domainName, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(deniedDomain)
	}
}

// Closing the connection interrupts in-flight I/O even on context cancellation
// without a deadline; the pinned DNS library only applies deadlines to I/O.
func exchangeDNSContext(ctx context.Context, client *dns.Client, request *dns.Msg, address string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	response, _, err := client.ExchangeWithConn(request, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}

// Clone public settings without copying the DNS client's internal mutex.
func (r *DefaultResolver) queryClient() *dns.Client {
	source := r.client
	timeout := source.Timeout
	if timeout <= 0 {
		seconds := r.config.Timeout
		if seconds <= 0 {
			seconds = 5
		}
		if seconds > 30 {
			seconds = 30
		}
		timeout = time.Duration(seconds) * time.Second
	}
	return &dns.Client{
		Net: source.Net, UDPSize: source.UDPSize, TLSConfig: source.TLSConfig, Dialer: source.Dialer,
		Timeout: timeout, DialTimeout: source.DialTimeout, ReadTimeout: source.ReadTimeout, WriteTimeout: source.WriteTimeout,
		TsigSecret: source.TsigSecret, TsigProvider: source.TsigProvider, SingleInflight: source.SingleInflight,
	}
}

func sameDNSQuestion(a, b dns.Question) bool {
	if a.Qtype != b.Qtype || a.Qclass != b.Qclass {
		return false
	}
	var x, y [255]byte
	nx, ex := dns.PackDomainName(a.Name, x[:], 0, nil, false)
	ny, ey := dns.PackDomainName(b.Name, y[:], 0, nil, false)
	if ex != nil || ey != nil || nx != ny || nx > len(x) {
		return false
	}
	// Compare decoded wire bytes with DNS's ASCII-only case folding.
	for i := 0; i < nx; i++ {
		c, d := x[i], y[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if d >= 'A' && d <= 'Z' {
			d += 'a' - 'A'
		}
		if c != d {
			return false
		}
	}
	return true
}
