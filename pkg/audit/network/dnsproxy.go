package network

import (
	"fmt"
	"net"
	"strings"

	"culinux/pkg/config"
	log "culinux/pkg/log"

	"github.com/miekg/dns"
)

const (
	dockerDNSBindAddress = "172.17.0.1"
	hostDNSBindAddress   = "127.0.0.1"
)

type DNSProxy struct {
	client    *dns.Client
	dnsConfig *dns.ClientConfig
	manager   *Manager
}

func dnsResponseToDNSAnswer(response *dns.Msg) *DNSAnswer {
	dnsAnswer := DNSAnswer{}
	if len(response.Question) == 1 {
		dnsAnswer.QueryType = response.Question[0].Qtype
	}
	for _, answer := range response.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			if record, ok := answer.(*dns.A); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, record.A)
				if len(dnsAnswer.Addresses) == 1 || record.Hdr.Ttl < dnsAnswer.TTL {
					dnsAnswer.TTL = record.Hdr.Ttl
				}
			}
		case dns.TypeAAAA:
			if record, ok := answer.(*dns.AAAA); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, record.AAAA)
				if len(dnsAnswer.Addresses) == 1 || record.Hdr.Ttl < dnsAnswer.TTL {
					dnsAnswer.TTL = record.Hdr.Ttl
				}
			}
		}
	}

	return &dnsAnswer
}

func updateDNSCache(fqdn string, dnsAnswer *DNSAnswer, caches ...*dnsNameCache) {
	cache := dnsCache
	if len(caches) > 0 {
		cache = caches[0]
	}
	cache.Replace(fqdn, dnsAnswer.QueryType, dnsAnswer.Addresses, dnsAnswer.TTL)
}

func (this *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	if r.Opcode != dns.OpcodeQuery {
		msg.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(&msg)
		return
	}
	if len(r.Question) != 1 {
		msg.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(&msg)
		return
	}

	msg.Authoritative = true
	for i, q := range r.Question {
		fqdn := msg.Question[i].Name
		res, err := this.resolve(fqdn, q.Qtype)
		if err != nil {
			log.Error(err)
			continue
		}

		msg.Answer = append(msg.Answer, res.Answer...)
		dnsAnswer := dnsResponseToDNSAnswer(res)
		dnsAnswer.Domain = fqdn

		updateDNSCache(fqdn, dnsAnswer, this.manager.dnsCache)

		for _, allowedDomain := range this.manager.config.Domain.Allow {
			if strings.EqualFold(toFqdn(allowedDomain), fqdn) {
				this.manager.updateAllowedFQDNist(dnsAnswer)
				break
			}
		}

		for _, deniedDomain := range this.manager.config.Domain.Deny {
			if strings.EqualFold(toFqdn(deniedDomain), fqdn) {
				this.manager.updateDeniedFQDNList(dnsAnswer)
				break
			}
		}

		log.Debug(fmt.Sprintf("Domain resolved: %s (%d)\n", fqdn, q.Qtype))
		log.Debug(fmt.Sprintf("Current DNS cache entries: %d", this.manager.dnsCache.Len()))
	}

	w.WriteMsg(&msg)
}

func (this *DNSProxy) resolve(domainName string, queryType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(domainName, queryType)
	m.RecursionDesired = true

	res, _, err := this.client.Exchange(m, net.JoinHostPort(this.dnsConfig.Servers[0], "53"))
	if err != nil {
		return nil, err
	}

	return res, err
}

func createDNSConfig(dnsProxyConfig config.DNSProxyConfig) (*dns.ClientConfig, error) {
	dnsConfig := &dns.ClientConfig{
		Servers: dnsProxyConfig.Upstreams,
	}

	return dnsConfig, nil
}

func (mgr *Manager) StartDNSServer(bindAddress string) error {
	dnsConfig, err := createDNSConfig(mgr.config.DNSProxyConfig)
	if err != nil {
		return err
	}

	srv := &dns.Server{Addr: bindAddress + ":53", Net: "udp"}
	srv.Handler = &DNSProxy{
		client:    new(dns.Client),
		dnsConfig: dnsConfig,
		manager:   mgr,
	}

	if err := srv.ListenAndServe(); err != nil {
		return err
	}

	return nil
}
