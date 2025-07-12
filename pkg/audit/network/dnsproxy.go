package network

import (
	"fmt"

	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/miekg/dns"
)

const (
	DockerDNSBindAddress = "172.17.0.1"
	HostDNSBindAddress   = "127.0.0.1"
)

// DNSProxyServer DNS 代理服务器
type DNSProxyServer struct {
	dnsClient  *dns.Client
	dnsConfig  *dns.ClientConfig
	controller *NetworkController
}

// ConvertDNSResponseToAnswer 将 DNS 响应转换为 DNSAnswer 结构体
func ConvertDNSResponseToAnswer(response *dns.Msg) *DNSAnswer {
	dnsAnswer := DNSAnswer{}
	for _, answer := range response.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			if record, ok := answer.(*dns.A); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, record.A)
				dnsAnswer.TTL = record.Hdr.Ttl
			}
		case dns.TypeAAAA:
			if record, ok := answer.(*dns.AAAA); ok {
				dnsAnswer.Addresses = append(dnsAnswer.Addresses, record.AAAA)
				dnsAnswer.TTL = record.Hdr.Ttl
			}
		}
	}

	return &dnsAnswer
}

// UpdateDNSCache 更新 DNS 缓存
func UpdateDNSCache(fqdn string, dnsAnswer *DNSAnswer) {
	for _, addr := range dnsAnswer.Addresses {
		dnsCache[addr.String()] = fqdn
	}
}

// ServeDNS 处理 DNS 请求
func (proxy *DNSProxyServer) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	responseMsg := dns.Msg{}
	responseMsg.SetReply(request)

	responseMsg.Authoritative = true
	for idx, question := range request.Question {
		fqdn := responseMsg.Question[idx].Name
		resolvedMsg, err := proxy.resolveDNS(fqdn, question.Qtype)
		if err != nil {
			log.Error(err)
			continue
		}

		responseMsg.Answer = append(responseMsg.Answer, resolvedMsg.Answer...)
		dnsAnswer := ConvertDNSResponseToAnswer(resolvedMsg)
		dnsAnswer.Domain = fqdn

		UpdateDNSCache(fqdn, dnsAnswer)

		for _, allowedDomain := range proxy.controller.settings.Domain.Allow {
			if ConvertToFQDN(allowedDomain) == fqdn {
				proxy.controller.updatePermittedFQDNList(dnsAnswer)
				break
			}
		}

		for _, deniedDomain := range proxy.controller.settings.Domain.Deny {
			if ConvertToFQDN(deniedDomain) == fqdn {
				proxy.controller.updateRestrictedFQDNList(dnsAnswer)
				break
			}
		}

		log.Debug(fmt.Sprintf("Resolved domain: %s (type %d)", fqdn, question.Qtype))
		log.Debug(fmt.Sprintf("Current DNS cache: %#v", dnsCache))
	}

	writer.WriteMsg(&responseMsg)
}

// resolveDNS 解析 DNS 请求
func (proxy *DNSProxyServer) resolveDNS(domainName string, queryType uint16) (*dns.Msg, error) {
	dnsMsg := new(dns.Msg)
	dnsMsg.SetQuestion(domainName, queryType)
	dnsMsg.RecursionDesired = true

	resolvedMsg, _, err := proxy.dnsClient.Exchange(dnsMsg, proxy.dnsConfig.Servers[0]+":53")
	if err != nil {
		return nil, err
	}

	return resolvedMsg, nil
}

// CreateDNSConfig 创建 DNS 配置
func CreateDNSConfig(dnsProxyConfig config.DNSProxyConfig) (*dns.ClientConfig, error) {
	dnsConfig := &dns.ClientConfig{
		Servers: dnsProxyConfig.Upstreams,
	}

	return dnsConfig, nil
}

// LaunchDNSServer 启动 DNS 服务器
func (nc *NetworkController) LaunchDNSServer(bindAddress string) error {
	dnsConfig, err := CreateDNSConfig(nc.settings.DNSProxyConfig)
	if err != nil {
		return err
	}

	dnsServer := &dns.Server{Addr: bindAddress + ":53", Net: "udp"}
	dnsServer.Handler = &DNSProxyServer{
		dnsClient:  new(dns.Client),
		dnsConfig:  dnsConfig,
		controller: nc,
	}

	if err := dnsServer.ListenAndServe(); err != nil {
		return err
	}

	return nil
}
