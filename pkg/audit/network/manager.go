package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/aquasecurity/libbpfgo"
	"github.com/miekg/dns"
)

const (
	MODE_MONITOR uint32 = 0
	MODE_BLOCK   uint32 = 1

	TARGET_HOST      uint32 = 0
	TARGET_CONTAINER uint32 = 1

	// BPF Map Names (同步 restricted-network.bpf.c 中的变量名)
	NET_SECURITY_POLICY_MAP_NAME  = "net_security_policy_map"
	PERMITTED_IPV4_CIDR_MAP_NAME  = "permitted_ipv4_cidr"
	PERMITTED_IPV6_CIDR_MAP_NAME  = "permitted_ipv6_cidr"
	RESTRICTED_IPV4_CIDR_MAP_NAME = "restricted_ipv4_cidr"
	RESTRICTED_IPV6_CIDR_MAP_NAME = "restricted_ipv6_cidr"
	PERMITTED_USER_MAP_NAME       = "permitted_user_map"
	BLOCKED_USER_MAP_NAME         = "blocked_user_map"
	PERMITTED_GROUP_MAP_NAME      = "permitted_group_map"
	BLOCKED_GROUP_MAP_NAME        = "blocked_group_map"
	PERMITTED_CMD_MAP_NAME        = "permitted_cmd_map"
	BLOCKED_CMD_MAP_NAME          = "blocked_cmd_map"

	/*
	   +---------------+---------------+-------------------+-------------------+-------------------+
	   | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12  | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
	   +---------------+---------------+-------------------+-------------------+-------------------+
	   |      MODE     |     TARGET    | Allow Command Size|  Allow UID Size   | Allow GID Size    |
	   +---------------+---------------+-------------------+-------------------+-------------------+
	*/

	MAP_SIZE                = 20
	MAP_MODE_START          = 0
	MAP_MODE_END            = 4
	MAP_TARGET_START        = 4
	MAP_TARGET_END          = 8
	MAP_ALLOW_COMMAND_INDEX = 8
	MAP_ALLOW_UID_INDEX     = 12
	MAP_ALLOW_GID_INDEX     = 16
)

// NetworkController 管理网络审计的控制器
type NetworkController struct {
	bpfModule   *libbpfgo.Module
	settings    *config.Config
	ringBuffer  *libbpfgo.RingBuffer
	dnsResolver DNSResolver
	dnsCache    map[string]string
}

// IPAddress 表示一个 IP 地址及其 CIDR 掩码
type IPAddress struct {
	ipAddr   net.IP
	cidrMask net.IPMask
	bpfKey   []byte
}

// IsIPv6 判断是否为 IPv6 地址
func (ip *IPAddress) IsIPv6() bool {
	return ip.ipAddr.To4() == nil
}

// GenerateBPFKey 将 IP 地址转换为 BPF 映射的键
func (ip *IPAddress) GenerateBPFKey() []byte {
	ipNet := net.IPNet{IP: ip.ipAddr.Mask(ip.cidrMask), Mask: ip.cidrMask}

	if ip.IsIPv6() {
		ip.bpfKey = convertIPv6ToBPFKey(ipNet)
	} else {
		ip.bpfKey = convertIPv4ToBPFKey(ipNet)
	}

	return ip.bpfKey
}

// DNSResolver 定义 DNS 解析接口
type DNSResolver interface {
	ResolveDNS(host string, recordType uint16) (*DNSAnswer, error)
}

// DefaultResolver 默认的 DNS 解析器实现
type DefaultResolver struct {
	dnsConfig     *dns.ClientConfig
	dnsClient     *dns.Client
	dnsMessage    *dns.Msg
	syncMutex     sync.Mutex
	resolvConfBak []byte
}

// ConfigureBPFMap 配置 BPF 映射
func (nc *NetworkController) ConfigureBPFMap() error {
	nc.initializeDNSCache()

	if err := nc.configurePolicyMap(); err != nil {
		return err
	}
	if err := nc.configurePermittedCIDRList(); err != nil {
		return err
	}
	if err := nc.configureRestrictedCIDRList(); err != nil {
		return err
	}

	if !nc.settings.DNSProxyConfig.Enable {
		if err := nc.initializeDomainList(); err != nil {
			return err
		}
	}

	if err := nc.configurePermittedCommandList(); err != nil {
		return err
	}
	if err := nc.configureBlockedCommandList(); err != nil {
		return err
	}
	if err := nc.configurePermittedUserList(); err != nil {
		return err
	}
	if err := nc.configureBlockedUserList(); err != nil {
		return err
	}
	if err := nc.configurePermittedGroupList(); err != nil {
		return err
	}
	if err := nc.configureBlockedGroupList(); err != nil {
		return err
	}
	return nil
}

// Start 启动网络审计
func (nc *NetworkController) Start(eventChan chan []byte) error {
	rb, err := nc.bpfModule.InitRingBuf("network_audit_logs", eventChan)
	if err != nil {
		return err
	}

	rb.Start()
	nc.ringBuffer = rb

	return nil
}

// Stop 停止网络审计
func (nc *NetworkController) Stop() {
	nc.ringBuffer.Stop()
}

// Close 关闭网络审计
func (nc *NetworkController) Close() {
	nc.ringBuffer.Close()
}

// AttachBPFPrograms 附加 BPF 程序
func (nc *NetworkController) AttachBPFPrograms() error {
	programNames := []string{"handle_socket_connect", "handle_socket_bind"}
	for _, progName := range programNames {
		prog, err := nc.bpfModule.GetProgram(progName)
		if err != nil {
			return err
		}

		_, err = prog.AttachLSM()
		if err != nil {
			return err
		}

		log.Debug(fmt.Sprintf("BPF program %s attached successfully.", progName))
	}

	return nil
}

// configureMode 配置模式（监控或阻止）
func (nc *NetworkController) configureMode(bpfMap *libbpfgo.BPFMap, keyData []byte) []byte {
	if nc.settings.IsRestrictedMode("network") {
		binary.LittleEndian.PutUint32(keyData[MAP_MODE_START:MAP_MODE_END], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(keyData[MAP_MODE_START:MAP_MODE_END], MODE_MONITOR)
	}

	return keyData
}

// configureTarget 配置目标（主机或容器）
func (nc *NetworkController) configureTarget(bpfMap *libbpfgo.BPFMap, keyData []byte) []byte {
	if nc.settings.IsOnlyContainer("network") {
		binary.LittleEndian.PutUint32(keyData[MAP_TARGET_START:MAP_TARGET_END], TARGET_CONTAINER)
	} else {
		binary.LittleEndian.PutUint32(keyData[MAP_TARGET_START:MAP_TARGET_END], TARGET_HOST)
	}

	return keyData
}

// configurePolicyMap 配置网络安全策略映射
func (nc *NetworkController) configurePolicyMap() error {
	policyMap, err := nc.bpfModule.GetMap(NET_SECURITY_POLICY_MAP_NAME)
	if err != nil {
		return err
	}

	keyData := make([]byte, MAP_SIZE)

	keyData = nc.configureMode(policyMap, keyData)
	keyData = nc.configureTarget(policyMap, keyData)

	binary.LittleEndian.PutUint32(keyData[MAP_ALLOW_COMMAND_INDEX:MAP_ALLOW_COMMAND_INDEX+4], uint32(len(nc.settings.RestrictedNetworkConfig.Command.Allow)))
	binary.LittleEndian.PutUint32(keyData[MAP_ALLOW_UID_INDEX:MAP_ALLOW_UID_INDEX+4], uint32(len(nc.settings.RestrictedNetworkConfig.UID.Allow)))
	binary.LittleEndian.PutUint32(keyData[MAP_ALLOW_GID_INDEX:MAP_ALLOW_GID_INDEX+4], uint32(len(nc.settings.RestrictedNetworkConfig.GID.Allow)))

	mapKey := uint8(0)
	err = policyMap.Update(unsafe.Pointer(&mapKey), unsafe.Pointer(&keyData[0]))
	if err != nil {
		return err
	}

	return nil
}

// configurePermittedCommandList 配置允许的命令列表
func (nc *NetworkController) configurePermittedCommandList() error {
	cmdMap, err := nc.bpfModule.GetMap(PERMITTED_CMD_MAP_NAME)
	if err != nil {
		return err
	}

	for _, cmd := range nc.settings.RestrictedNetworkConfig.Command.Allow {
		keyData := convertBytesToBPFKey([]byte(cmd))
		valueData := uint8(0)
		err = cmdMap.Update(unsafe.Pointer(&keyData[0]), unsafe.Pointer(&valueData))
		if err != nil {
			return err
		}
	}

	return nil
}

// configureBlockedCommandList 配置禁止的命令列表
func (nc *NetworkController) configureBlockedCommandList() error {
	cmdMap, err := nc.bpfModule.GetMap(BLOCKED_CMD_MAP_NAME)
	if err != nil {
		return err
	}

	for _, cmd := range nc.settings.RestrictedNetworkConfig.Command.Deny {
		keyData := convertBytesToBPFKey([]byte(cmd))
		valueData := uint8(0)
		err = cmdMap.Update(unsafe.Pointer(&keyData[0]), unsafe.Pointer(&valueData))
		if err != nil {
			return err
		}
	}

	return nil
}

// configurePermittedUserList 配置允许的用户列表
func (nc *NetworkController) configurePermittedUserList() error {
	userMap, err := nc.bpfModule.GetMap(PERMITTED_USER_MAP_NAME)
	if err != nil {
		return err
	}
	for _, uid := range nc.settings.RestrictedNetworkConfig.UID.Allow {
		keyData := convertUintToBPFKey(uid)
		valueData := uint8(0)
		err = userMap.Update(unsafe.Pointer(&keyData[0]), unsafe.Pointer(&valueData))
		if err != nil {
			return err
		}
	}

	return nil
}

// configureBlockedUserList 配置禁止的用户列表
func (nc *NetworkController) configureBlockedUserList() error {
	userMap, err := nc.bpfModule.GetMap(BLOCKED_USER_MAP_NAME)
	if err != nil {
		return err
	}
	for _, uid := range nc.settings.RestrictedNetworkConfig.UID.Deny {
		keyData := convertUintToBPFKey(uid)
		valueData := uint8(0)
		err = userMap.Update(unsafe.Pointer(&keyData[0]), unsafe.Pointer(&valueData))
		if err != nil {
			return err
		}
	}

	return nil
}

// configurePermittedGroupList 配置允许的组列表
func (nc *NetworkController) configurePermittedGroupList() error {
	groupMap, err := nc.bpfModule.GetMap(PERMITTED_GROUP_MAP_NAME)
	if err != nil {
		return err
	}
	for _, gid := range nc.settings.RestrictedNetworkConfig.GID.Allow {
		keyData := convertUintToBPFKey(gid)
		valueData := uint8(0)
		err = groupMap.Update(unsafe.Pointer(&keyData[0]), unsafe.Pointer(&valueData))
		if err != nil {
			return err
		}
	}

	return nil
}

// configureBlockedGroupList 配置禁止的组列表
func (nc *NetworkController) configureBlockedGroupList() error {
	groupMap, err := nc.bpfModule.GetMap(BLOCKED_GROUP_MAP_NAME)
	if err != nil {
		return err
	}
	for _, gid := range nc.settings.RestrictedNetworkConfig.GID.Deny {
		keyData := convertUintToBPFKey(gid)
		valueData := uint8(0)
		err = groupMap.Update(unsafe.Pointer(&keyData[0]), unsafe.Pointer(&valueData))
		if err != nil {
			return err
		}
	}

	return nil
}

// configurePermittedCIDRList 配置允许的 CIDR 列表
func (nc *NetworkController) configurePermittedCIDRList() error {
	for _, addr := range nc.settings.RestrictedNetworkConfig.CIDR.Allow {
		allowedAddr, err := convertCIDRToBPFKey(addr)
		if err != nil {
			return err
		}
		if allowedAddr.IsIPv6() {
			err = nc.updateCIDRList(allowedAddr, PERMITTED_IPV6_CIDR_MAP_NAME)
			if err != nil {
				return err
			}
		} else {
			err = nc.updateCIDRList(allowedAddr, PERMITTED_IPV4_CIDR_MAP_NAME)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// configureRestrictedCIDRList 配置禁止的 CIDR 列表
func (nc *NetworkController) configureRestrictedCIDRList() error {
	for _, addr := range nc.settings.RestrictedNetworkConfig.CIDR.Deny {
		restrictedAddr, err := convertCIDRToBPFKey(addr)
		if err != nil {
			return err
		}
		if restrictedAddr.IsIPv6() {
			err = nc.updateCIDRList(restrictedAddr, RESTRICTED_IPV6_CIDR_MAP_NAME)
			if err != nil {
				return err
			}
		} else {
			err = nc.updateCIDRList(restrictedAddr, RESTRICTED_IPV4_CIDR_MAP_NAME)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// initializeDomainList 初始化域名列表
func (nc *NetworkController) initializeDomainList() error {
	for _, domain := range nc.settings.RestrictedNetworkConfig.Domain.Deny {
		answer, err := nc.ResolveIPv4Address(domain)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve A record for %s: %s", domain, err))
			continue
		}

		log.Debug(fmt.Sprintf("Resolved A record for %s: %#v, TTL: %d", answer.Domain, answer.Addresses, answer.TTL))
		err = nc.updateRestrictedFQDNList(answer)
		if err != nil {
			return err
		}

		answer, err = nc.ResolveIPv6Address(domain)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve AAAA record for %s: %s", domain, err))
			continue
		}

		log.Debug(fmt.Sprintf("Resolved AAAA record for %s: %#v, TTL: %d", answer.Domain, answer.Addresses, answer.TTL))
		err = nc.updateRestrictedFQDNList(answer)
		if err != nil {
			return err
		}
	}

	for _, domain := range nc.settings.RestrictedNetworkConfig.Domain.Allow {
		answer, err := nc.ResolveIPv4Address(domain)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve A record for %s: %s", domain, err))
			continue
		}

		log.Debug(fmt.Sprintf("Resolved A record for %s: %#v, TTL: %d", answer.Domain, answer.Addresses, answer.TTL))
		err = nc.updatePermittedFQDNList(answer)
		if err != nil {
			return err
		}

		answer, err = nc.ResolveIPv6Address(domain)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to resolve AAAA record for %s: %s", domain, err))
			continue
		}

		log.Debug(fmt.Sprintf("Resolved AAAA record for %s: %#v, TTL: %d", answer.Domain, answer.Addresses, answer.TTL))
		err = nc.updatePermittedFQDNList(answer)
		if err != nil {
			return err
		}
	}

	return nil
}

// updatePermittedFQDNList 更新允许的 FQDN 列表
func (nc *NetworkController) updatePermittedFQDNList(answer *DNSAnswer) error {
	allowedAddrs, err := convertDomainToBPFKey(answer.Domain, answer.Addresses)
	if err != nil {
		return err
	}

	for _, addr := range allowedAddrs {
		if addr.IsIPv6() {
			if err = nc.updateCIDRList(addr, PERMITTED_IPV6_CIDR_MAP_NAME); err != nil {
				return err
			}
		} else {
			if err = nc.updateCIDRList(addr, PERMITTED_IPV4_CIDR_MAP_NAME); err != nil {
				return err
			}
		}
	}

	return nil
}

// updateRestrictedFQDNList 更新禁止的 FQDN 列表
func (nc *NetworkController) updateRestrictedFQDNList(answer *DNSAnswer) error {
	restrictedAddrs, err := convertDomainToBPFKey(answer.Domain, answer.Addresses)
	if err != nil {
		return err
	}

	for _, addr := range restrictedAddrs {
		if addr.IsIPv6() {
			err = nc.updateCIDRList(addr, RESTRICTED_IPV6_CIDR_MAP_NAME)
			if err != nil {
				return err
			}
		} else {
			err = nc.updateCIDRList(addr, RESTRICTED_IPV4_CIDR_MAP_NAME)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// deleteCIDRListKey 从 CIDR 列表中删除键
func (nc *NetworkController) deleteCIDRListKey(mapName string, keyData []byte) error {
	cidrMap, err := nc.bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}

	if err := cidrMap.DeleteKey(unsafe.Pointer(&keyData[0])); err != nil {
		return err
	}
	return nil
}

// updateCIDRList 更新 CIDR 列表
func (nc *NetworkController) updateCIDRList(addr IPAddress, mapName string) error {
	cidrMap, err := nc.bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}
	valueData := uint8(0)
	err = cidrMap.Update(unsafe.Pointer(&addr.bpfKey[0]), unsafe.Pointer(&valueData))
	if err != nil {
		return err
	}
	return nil
}

// convertCIDRToBPFKey 将 CIDR 转换为 BPF 键
func convertCIDRToBPFKey(cidr string) (IPAddress, error) {
	ipAddr := IPAddress{}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ipAddr, err
	}
	ipAddr.ipAddr = ipNet.IP
	ipAddr.cidrMask = ipNet.Mask
	ipAddr.GenerateBPFKey()
	return ipAddr, nil
}

// convertDomainToBPFKey 将域名解析结果转换为 BPF 键
func convertDomainToBPFKey(host string, addresses []net.IP) ([]IPAddress, error) {
	var addrList []IPAddress
	for _, addr := range addresses {
		ipAddr := IPAddress{ipAddr: addr}
		if ipAddr.IsIPv6() {
			ipAddr.cidrMask = net.CIDRMask(128, 128)
		} else {
			ipAddr.cidrMask = net.CIDRMask(32, 32)
		}
		ipAddr.GenerateBPFKey()
		addrList = append(addrList, ipAddr)
	}

	return addrList, nil
}

// convertIPv4ToBPFKey 将 IPv4 网络转换为 BPF 键
func convertIPv4ToBPFKey(ipNet net.IPNet) []byte {
	keyData := make([]byte, 16)
	prefixLen, _ := ipNet.Mask.Size()

	binary.LittleEndian.PutUint32(keyData[0:4], uint32(prefixLen))
	copy(keyData[4:], ipNet.IP)

	return keyData
}

// convertIPv6ToBPFKey 将 IPv6 网络转换为 BPF 键
func convertIPv6ToBPFKey(ipNet net.IPNet) []byte {
	keyData := make([]byte, 20)
	prefixLen, _ := ipNet.Mask.Size()

	binary.LittleEndian.PutUint32(keyData[0:4], uint32(prefixLen))
	copy(keyData[4:], ipNet.IP)

	return keyData
}

// convertBytesToBPFKey 将字节数组转换为 BPF 键
func convertBytesToBPFKey(data []byte) []byte {
	keyData := make([]byte, 16)
	copy(keyData[0:], data)
	return keyData
}

// convertUintToBPFKey 将无符号整数转换为 BPF 键
func convertUintToBPFKey(value uint) []byte {
	keyData := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyData[0:4], uint32(value))
	return keyData
}

// initializeDNSCache 初始化 DNS 缓存
func (nc *NetworkController) initializeDNSCache() {
	InitializeDNSCache()
}
