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
	QueryType uint16
	Domain    string
	Addresses []net.IP
	TTL       uint32
}

// dnsCache stores resolved domain-to-IP mappings for periodic name resolution.
var dnsCache = newDNSCache()

// initDNSCache initializes the DNS cache map if it has not been created yet.
func initDNSCache() {
	if dnsCache == nil {
		dnsCache = newDNSCache()
	}
}

// To FQDN format
// e.g. example.com -> example.com.
// toFqdn converts a domain name to FQDN format by appending a trailing dot.
func toFqdn(domainName string) string {
	if domainName == "" {
		return ""
	}
	return dns.Fqdn(domainName)
}

func (r *DefaultResolver) exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	failures := []string{}
	var lastReply *dns.Msg
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

		if !validDNSReply(message, res) {
			failures = append(failures, fmt.Sprintf("%s: DNS response identity mismatch", server))
			continue
		}
		if res.Truncated {
			client := r.queryClient()
			if client.Net != "" && !strings.HasPrefix(client.Net, "udp") {
				return nil, errors.New("truncated TCP DNS response")
			}
			client.Net = strings.Replace(client.Net, "udp", "tcp", 1)
			if client.Net == "" {
				client.Net = "tcp"
			}
			res, err = exchangeDNSContext(ctx, client, message, net.JoinHostPort(server, port))
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				failures = append(failures, fmt.Sprintf("%s TCP: %v", server, err))
				continue
			}
			if !validDNSReply(message, res) || res.Truncated {
				failures = append(failures, fmt.Sprintf("%s: invalid or truncated TCP DNS response", server))
				continue
			}
		}
		if res.Rcode == dns.RcodeServerFailure || res.Rcode == dns.RcodeRefused {
			lastReply = res
			continue
		}
		return res, nil
	}
	if lastReply != nil {
		return lastReply, nil
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
	if host == "" {
		return nil, errors.New("DNS host must not be empty")
	}
	if r == nil || r.config == nil || r.client == nil {
		return nil, errors.New("DNS resolver is not initialized")
	}
	ctx, cancel := context.WithTimeout(ctx, r.queryClient().Timeout)
	defer cancel()
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

	records, err := responseChain(res.Answer, toFqdn(host), recordType)
	if err != nil {
		return nil, err
	}
	answer := DNSAnswer{Domain: host}
	if len(records) > 0 {
		answer.TTL = records[0].Header().Ttl
	}
	for _, rr := range records {
		if rr.Header().Ttl < answer.TTL {
			answer.TTL = rr.Header().Ttl
		}
		switch recordType {
		case dns.TypeA:
			if record, ok := rr.(*dns.A); ok {
				answer.Addresses = append(answer.Addresses, record.A)
			}
		case dns.TypeAAAA:
			if record, ok := rr.(*dns.AAAA); ok {
				answer.Addresses = append(answer.Addresses, record.AAAA)
			}
		}
	}

	if answer.Addresses == nil {
		return nil, fmt.Errorf("%s type %d: %w", host, recordType, ErrDNSNoData)
	}

	return &answer, nil
}

func (mgr *Manager) ResolveAddressv4(domain string) (*DNSAnswer, error) {
	answer, err := mgr.resolveAddress(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	return answer, nil
}

func (mgr *Manager) ResolveAddressv6(domain string) (*DNSAnswer, error) {
	answer, err := mgr.resolveAddress(domain, dns.TypeAAAA)
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
			return 5, err
		}
		err = mgr.updateAllowedFQDNist(answer)
		if err != nil {
			return 5, err
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	case dns.TypeAAAA:
		answer, err := mgr.ResolveAddressv6(domainName)
		if err != nil {
			return 5, err
		}
		err = mgr.updateAllowedFQDNist(answer)
		if err != nil {
			return 5, err
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
			return 5, err
		}
		err = mgr.updateDeniedFQDNList(answer)
		if err != nil {
			return 5, err
		}

		log.Debug(fmt.Sprintf("%s (A) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	case dns.TypeAAAA:
		answer, err := mgr.ResolveAddressv6(domainName)
		if err != nil {
			return 5, err
		}
		err = mgr.updateDeniedFQDNList(answer)
		if err != nil {
			return 5, err
		}

		log.Debug(fmt.Sprintf("%s (AAAA) is %#v, TTL is %d\n", answer.Domain, answer.Addresses, answer.TTL))
		return answer.TTL, nil
	}

	return 5, errors.New("invalid record type")
}

func (mgr *Manager) AsyncResolve() {
	mgr.lifecycleMu.Lock()
	defer mgr.lifecycleMu.Unlock()
	if mgr.stopDNS != nil || mgr.stopped || mgr.closed {
		return
	}
	if mgr.dnsContext == nil {
		mgr.dnsContext = context.Background()
	}
	mgr.dnsContext, mgr.stopDNS = context.WithCancel(mgr.dnsContext)
	mgr.refreshWG.Add(2 * (len(mgr.config.Domain.Allow) + len(mgr.config.Domain.Deny)))
	for _, allowedDomain := range mgr.config.RestrictedNetworkConfig.Domain.Allow {
		go func(domainName string) {
			defer mgr.refreshWG.Done()
			var retry refreshRetry
			for mgr.dnsContext.Err() == nil {
				ttl, err := mgr.resolveAndUpdateAllowedFQDNList(domainName, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				waitRefresh(mgr.dnsContext, retry.next(ttl, err))
			}
		}(allowedDomain)

		go func(domainName string) {
			defer mgr.refreshWG.Done()
			var retry refreshRetry
			for mgr.dnsContext.Err() == nil {
				ttl, err := mgr.resolveAndUpdateAllowedFQDNList(domainName, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				waitRefresh(mgr.dnsContext, retry.next(ttl, err))
			}
		}(allowedDomain)
	}

	for _, deniedDomain := range mgr.config.RestrictedNetworkConfig.Domain.Deny {
		go func(domainName string) {
			defer mgr.refreshWG.Done()
			var retry refreshRetry
			for mgr.dnsContext.Err() == nil {
				ttl, err := mgr.resolveAndUpdateDeniedFQDNList(domainName, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				waitRefresh(mgr.dnsContext, retry.next(ttl, err))
			}
		}(deniedDomain)

		go func(domainName string) {
			defer mgr.refreshWG.Done()
			var retry refreshRetry
			for mgr.dnsContext.Err() == nil {
				ttl, err := mgr.resolveAndUpdateDeniedFQDNList(domainName, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				waitRefresh(mgr.dnsContext, retry.next(ttl, err))
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
	return sameDNSName(a.Name, b.Name)
}

func sameDNSName(a, b string) bool {
	var x, y [255]byte
	nx, ex := dns.PackDomainName(a, x[:], 0, nil, false)
	ny, ey := dns.PackDomainName(b, y[:], 0, nil, false)
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

var ErrDNSAliasCycle = errors.New("DNS alias cycle")
var ErrDNSAliasLimit = errors.New("DNS alias chain exceeds 16 hops")

// Only follow aliases carried in this response; never start implicit queries.
func responseChain(records []dns.RR, name string, recordType uint16) ([]dns.RR, error) {
	var relevant []dns.RR
	var seen []string
	for hops := 0; hops <= 16; hops++ {
		for _, previous := range seen {
			if sameDNSName(previous, name) {
				return nil, ErrDNSAliasCycle
			}
		}
		seen = append(seen, name)
		target := ""
		address := false
		for _, rr := range records {
			if rr.Header().Class != dns.ClassINET || !sameDNSName(name, rr.Header().Name) {
				continue
			}
			if alias, ok := rr.(*dns.CNAME); ok {
				if target != "" && !sameDNSName(target, alias.Target) {
					return nil, errors.New("conflicting CNAME targets")
				}
				target = alias.Target
				relevant = append(relevant, rr)
			} else {
				if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
					address = true
				}
				if rr.Header().Rrtype == recordType {
					relevant = append(relevant, rr)
				}
			}
		}
		if target != "" && address {
			return nil, errors.New("CNAME and address records share an owner")
		}
		if target == "" {
			return relevant, nil
		}
		name = target
	}
	return nil, ErrDNSAliasLimit
}

func validDNSReply(request, response *dns.Msg) bool {
	return response != nil && response.Response && response.Opcode == request.Opcode && len(response.Question) == 1 && sameDNSQuestion(request.Question[0], response.Question[0])
}

// Preserve zero in DNS answers, but never let a zero TTL spin refresh workers.
func refreshDelay(ttl uint32) time.Duration {
	if ttl == 0 {
		return time.Second
	}
	return time.Duration(ttl) * time.Second
}

func (mgr *Manager) resolveAddress(domain string, kind uint16) (*DNSAnswer, error) {
	var answer *DNSAnswer
	var err error
	if resolver, ok := mgr.dnsResolver.(interface {
		ResolveContext(context.Context, string, uint16) (*DNSAnswer, error)
	}); ok && mgr.dnsContext != nil {
		answer, err = resolver.ResolveContext(mgr.dnsContext, domain, kind)
	} else {
		if mgr.dnsContext != nil && mgr.dnsContext.Err() != nil {
			return nil, mgr.dnsContext.Err()
		}
		answer, err = mgr.dnsResolver.Resolve(domain, kind)
	}
	if answer == nil && err == nil {
		return nil, fmt.Errorf("resolver returned nil answer for %s", domain)
	}
	if err == nil && len(answer.Addresses) == 0 {
		return nil, fmt.Errorf("%s type %d: %w", domain, kind, ErrDNSNoData)
	}
	return answer, err
}
