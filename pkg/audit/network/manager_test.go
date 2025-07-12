package network

import (
	"net"
	"testing"

	"safeguard/pkg/config"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// MockDNSResolver 模拟 DNS 解析器
type MockDNSResolver struct {
	dnsConfig  *dns.ClientConfig
	dnsClient  *dns.Client
	dnsMessage *dns.Msg
}

// Resolve 模拟 DNS 解析
func (r *MockDNSResolver) Resolve(host string, recordType uint16) (DNSAnswer, error) {
	dnsAnswer := DNSAnswer{Domain: host}
	dnsAnswer.Addresses = []net.IP{
		net.IPv4(192, 168, 1, 1),
		net.IPv4(10, 0, 1, 1),
	}
	dnsAnswer.TTL = 1234

	return dnsAnswer, nil
}

// TestConvertCIDRToBPFKey 测试将 CIDR 转换为 BPF 键
func TestConvertCIDRToBPFKey(t *testing.T) {
	testCases := []struct {
		testName string
		cidr     string
		expected IPAddress
	}{
		{
			testName: "Parsing the CIDR and returning IPAddress{}",
			cidr:     "192.168.1.1/24",
			expected: IPAddress{
				ipAddr:   net.IP{0xc0, 0xa8, 0x1, 0x0},
				cidrMask: net.IPMask{0xff, 0xff, 0xff, 0x0},
				bpfKey:   []byte{0x18, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			ipAddr, err := convertCIDRToBPFKey(testCase.cidr)
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, ipAddr)
		})
	}
}

// TestGenerateBPFKey 测试生成 BPF 键
func TestGenerateBPFKey(t *testing.T) {
	testCases := []struct {
		testName  string
		ipAddress IPAddress
		expected  []byte
	}{
		{
			testName: "IPv4",
			ipAddress: IPAddress{
				ipAddr:   net.IP{0xc0, 0xa8, 0x1, 0x1},       // 192.168.1.1
				cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff}, // /32
			},
			expected: []byte{0x20, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			testName: "IPv6",
			ipAddress: IPAddress{
				ipAddr:   net.IP{0x20, 0x1, 0x39, 0x84, 0x39, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3},                // 2001:3984:3989::3
				cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // /128
			},
			expected: []byte{0x80, 0x0, 0x0, 0x0, 0x20, 0x1, 0x39, 0x84, 0x39, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			bpfKey := testCase.ipAddress.GenerateBPFKey()
			assert.Equal(t, testCase.expected, bpfKey)
		})
	}
}

// TestConvertDomainToBPFKey 测试将域名解析结果转换为 BPF 键
func TestConvertDomainToBPFKey(t *testing.T) {
	testCases := []struct {
		testName   string
		domainName string
		addresses  []net.IP
		expected   []IPAddress
	}{
		{
			testName:   "example.com",
			domainName: "example.com",
			addresses: []net.IP{
				{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1},
				{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x1, 0x1},
			},
			expected: []IPAddress{
				{
					ipAddr:   []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1},
					cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff},
					bpfKey:   []byte{0x20, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				},
				{
					ipAddr:   []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x1, 0x1},
					cidrMask: net.IPMask{0xff, 0xff, 0xff, 0xff},
					bpfKey:   []byte{0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			addrList, err := convertDomainToBPFKey(testCase.domainName, testCase.addresses)
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, addrList)
		})
	}
}

// createMockDNSResolver 创建模拟 DNS 解析器
func createMockDNSResolver() MockDNSResolver {
	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		panic(err)
	}
	resolver := MockDNSResolver{
		dnsConfig:  dnsConfig,
		dnsClient:  new(dns.Client),
		dnsMessage: new(dns.Msg),
	}

	return resolver
}

// loadTestConfig 加载测试配置文件
func loadTestConfig(configPath string) *config.Config {
	configData, err := config.NewConfig(configPath)
	if err != nil {
		panic(err)
	}
	return configData
}

// createTestManager 创建测试用的网络管理器
func createTestManager(configData *config.Config, dnsResolver DNSResolver) NetworkController {
	bpfModule, err := initializeBPFModule()
	if err != nil {
		panic(err)
	}

	testController := NetworkController{
		bpfModule:   bpfModule,
		settings:    configData,
		dnsResolver: dnsResolver,
	}

	err = testController.ConfigureBPFMap()
	if err != nil {
		panic(err)
	}

	return testController
}
