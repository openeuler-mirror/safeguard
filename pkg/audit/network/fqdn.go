package network

import (
	"errors"
	"fmt"
	"net"
	"time"

	log "safeguard/pkg/log"

	"github.com/miekg/dns"
)

// DNSAnswer DNS 解析结果
type DNSAnswer struct {
	Domain    string
	Addresses []net.IP
	TTL       uint32
}

var dnsCache map[string]string

// InitializeDNSCache 初始化 DNS 缓存
func InitializeDNSCache() {
	if dnsCache == nil {
		dnsCache = make(map[string]string)
	}
}

// ConvertToFQDN 将域名转换为 FQDN 格式
func ConvertToFQDN(domainName string) string {
	if domainName[len(domainName)-1:] == "." {
		return domainName
	}

	return domainName + "."
}

// ExchangeDNSMessage 执行 DNS 消息交换
func (resolver *DefaultResolver) ExchangeDNSMessage(message *dns.Msg) (*dns.Msg, error) {
	for _, server := range resolver.dnsConfig.Servers {
		resolvedMsg, _, err := resolver.dnsClient.Exchange(resolver.dnsMessage, server+":53")
		if err != nil {
			log.Error(err)
			continue
		}
		return resolvedMsg, nil
	}

	return nil, errors.New("DNS resolution failed")
}

// ResolveDNS 解析 DNS 记录
func (resolver *DefaultResolver) ResolveDNS(host string, recordType uint16) (*DNSAnswer, error) {
	resolver.syncMutex.Lock()

	resolver.dnsMessage.SetQuestion(ConvertToFQDN(host), recordType)
	resolver.dnsMessage.RecursionDesired = true

	resolvedMsg, err := resolver.ExchangeDNSMessage(resolver.dnsMessage)
	resolver.syncMutex.Unlock()

	if err != nil {
		return nil, err
	}

	if resolvedMsg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS resolution failed with return code %d", resolvedMsg.Rcode)
	}

	if len(resolvedMsg.Answer) == 0 {
		return nil, fmt.Errorf("No records found for %s (type %d)", host, recordType)
	}

	dnsAnswer := DNSAnswer{Domain: host}
	for _, record := range resolvedMsg.Answer {
		switch recordType {
		case dns.TypeA:
			if aRecord, ok := record.(*dns.A); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, aRecord.A)
				dnsAnswer.TTL = aRecord.Hdr.Ttl
			}
		case dns.TypeAAAA:
			if aaaaRecord, ok := record.(*dns.AAAA); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, aaaaRecord.AAAA)
				dnsAnswer.TTL = aaaaRecord.Hdr.Ttl
			}
		}
	}

	if dnsAnswer.Addresses == nil {
		return nil, fmt.Errorf("No records found for %s (type %d)", host, recordType)
	}

	return &dnsAnswer, nil
}

// ResolveIPv4Address 解析 IPv4 地址
func (nc *NetworkController) ResolveIPv4Address(domain string) (*DNSAnswer, error) {
	dnsAnswer, err := nc.dnsResolver.ResolveDNS(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	return dnsAnswer, nil
}

// ResolveIPv6Address 解析 IPv6 地址
func (nc *NetworkController) ResolveIPv6Address(domain string) (*DNSAnswer, error) {
	dnsAnswer, err := nc.dnsResolver.ResolveDNS(domain, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}

	return dnsAnswer, nil
}

// ResolveAndUpdatePermittedFQDNList 解析并更新允许的 FQDN 列表
func (nc *NetworkController) ResolveAndUpdatePermittedFQDNList(domainName string, recordType uint16) (uint32, error) {
	switch recordType {
	case dns.TypeA:
		dnsAnswer, err := nc.ResolveIPv4Address(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve A record for %s: %s", domainName, err))
			return 5, nil
		}
		err = nc.updatePermittedFQDNList(dnsAnswer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("Resolved A record for %s: %#v, TTL: %d", dnsAnswer.Domain, dnsAnswer.Addresses, dnsAnswer.TTL))
		return dnsAnswer.TTL, nil
	case dns.TypeAAAA:
		dnsAnswer, err := nc.ResolveIPv6Address(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve AAAA record for %s: %s", domainName, err))
			return 5, nil
		}
		err = nc.updatePermittedFQDNList(dnsAnswer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("Resolved AAAA record for %s: %#v, TTL: %d", dnsAnswer.Domain, dnsAnswer.Addresses, dnsAnswer.TTL))
		return dnsAnswer.TTL, nil
	}

	return 5, errors.New("invalid DNS record type")
}

// ResolveAndUpdateRestrictedFQDNList 解析并更新禁止的 FQDN 列表
func (nc *NetworkController) ResolveAndUpdateRestrictedFQDNList(domainName string, recordType uint16) (uint32, error) {
	switch recordType {
	case dns.TypeA:
		dnsAnswer, err := nc.ResolveIPv4Address(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve A record for %s: %s", domainName, err))
			return 5, nil
		}
		err = nc.updateRestrictedFQDNList(dnsAnswer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("Resolved A record for %s: %#v, TTL: %d", dnsAnswer.Domain, dnsAnswer.Addresses, dnsAnswer.TTL))
		return dnsAnswer.TTL, nil
	case dns.TypeAAAA:
		dnsAnswer, err := nc.ResolveIPv6Address(domainName)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve AAAA record for %s: %s", domainName, err))
			return 5, nil
		}
		err = nc.updateRestrictedFQDNList(dnsAnswer)
		if err != nil {
			return 5, nil
		}

		log.Debug(fmt.Sprintf("Resolved AAAA record for %s: %#v, TTL: %d", dnsAnswer.Domain, dnsAnswer.Addresses, dnsAnswer.TTL))
		return dnsAnswer.TTL, nil
	}

	return 5, errors.New("invalid DNS record type")
}

// AsyncResolveDNS 异步解析 DNS
func (nc *NetworkController) AsyncResolveDNS() {
	for _, allowedDomain := range nc.settings.RestrictedNetworkConfig.Domain.Allow {
		go func(domain string) {
			for {
				ttl, err := nc.ResolveAndUpdatePermittedFQDNList(domain, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(allowedDomain)

		go func(domain string) {
			for {
				ttl, err := nc.ResolveAndUpdatePermittedFQDNList(domain, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(allowedDomain)
	}

	for _, deniedDomain := range nc.settings.RestrictedNetworkConfig.Domain.Deny {
		go func(domain string) {
			for {
				ttl, err := nc.ResolveAndUpdateRestrictedFQDNList(domain, dns.TypeA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(deniedDomain)

		go func(domain string) {
			for {
				ttl, err := nc.ResolveAndUpdateRestrictedFQDNList(domain, dns.TypeAAAA)
				if err != nil {
					log.Error(err)
				}
				time.Sleep(time.Duration(ttl) * time.Second)
			}
		}(deniedDomain)
	}
}
