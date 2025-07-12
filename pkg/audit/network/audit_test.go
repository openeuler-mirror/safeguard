//go:build integration
// +build integration

package network

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"testing"
	"time"

	"safeguard/pkg/audit/helpers"
	"safeguard/pkg/config"

	"github.com/stretchr/testify/assert"
)

// TestAuditController 测试网络审计控制器
type TestAuditController struct {
	manager Manager
	command *exec.Cmd
}

// LaunchDockerCompose 启动 Docker Compose 服务
func LaunchDockerCompose() error {
	_, err := exec.Command("docker-compose", "-f", "../../../testdata/docker-compose.yml", "up", "-d").Output()
	if err != nil {
		return err
	}

	return nil
}

// TerminateDockerCompose 停止 Docker Compose 服务
func TerminateDockerCompose() {
	exec.Command("docker-compose", "-f", "../../../testdata/docker-compose.yml", "down").Run()
}

// TestMain 测试主函数
func TestMain(m *testing.M) {
	err := LaunchDockerCompose()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	result := m.Run()
	TerminateDockerCompose()
	os.Exit(result)
}

// TestIPv4ActionResult 测试 IPv4 动作结果
func TestIPv4ActionResult(t *testing.T) {
	testCases := []struct {
		name     string
		input    detectEventIPv4
		expected string
	}{
		{
			name: "Returns 'BLOCKED' if value `0` is returned",
			input: detectEventIPv4{
				SrcIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_BLOCKED,
				SockType:     TCP,
			},
			expected: ACTION_BLOCKED_STRING,
		},
		{
			name: "Returns 'MONITOR' if value `1` is returned",
			input: detectEventIPv4{
				SrcIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_MONITOR,
				SockType:     TCP,
			},
			expected: ACTION_MONITOR_STRING,
		},
		{
			name: "Returns 'unknown' if undefined value is returned.",
			input: detectEventIPv4{
				SrcIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstIP:        [4]byte{0x8, 0x8, 0x8, 0x8},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       10,
				SockType:     TCP,
			},
			expected: ACTION_UNKNOWN_STRING,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, testCase.input.ActionResult())
		})
	}
}

// TestIPv6ActionResult 测试 IPv6 动作结果
func TestIPv6ActionResult(t *testing.T) {
	testCases := []struct {
		name     string
		input    detectEventIPv6
		expected string
	}{
		{
			name: "Returns 'BLOCKED' iff value `0` is returned",
			input: detectEventIPv6{
				SrcIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_BLOCKED,
				SockType:     TCP,
			},
			expected: ACTION_BLOCKED_STRING,
		},
		{
			name: "Returns 'MONITOR' iff value `1` is returned",
			input: detectEventIPv6{
				SrcIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       ACTION_MONITOR,
				SockType:     TCP,
			},
			expected: ACTION_MONITOR_STRING,
		},
		{
			name: "Returns 'unknown' if undefined value is returned.",
			input: detectEventIPv6{
				SrcIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstIP:        [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44},
				DstPort:      80,
				LsmHookPoint: LSM_HOOK_POINT_CONNECT,
				Action:       10,
				SockType:     TCP,
			},
			expected: ACTION_UNKNOWN_STRING,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, testCase.input.ActionResult())
		})
	}
}

// TestIPv4BlockMode 测试 IPv4 阻止模式
func TestIPv4BlockMode(t *testing.T) {
	configPath := "../../../testdata/block_v4.yml"
	blockedAddr := "10.254.249.3"
	allowedAddr := "10.254.249.4"
	eventChan := make(chan []byte)
	auditController := executeAuditOnce(configPath, []string{"curl", fmt.Sprintf("http://%s", blockedAddr)}, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, eventHeader.EventType)

	body := eventBody.(detectEventIPv4)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, blockedAddr, byte2IPv4(body.DstIP))

	err = exec.Command("curl", fmt.Sprintf("http://%s", allowedAddr)).Run()
	assert.Nil(t, err)

	err = exec.Command("curl", fmt.Sprintf("http://%s", blockedAddr)).Run()
	assert.NotNil(t, err)

	auditController.manager.mod.Close()
}

// MockIntegrationDNSResolver 模拟集成测试的 DNS 解析器
type MockIntegrationDNSResolver struct{}

// Resolve 模拟 DNS 解析
func (r *MockIntegrationDNSResolver) Resolve(host string, recordType uint16) (*DNSAnswer, error) {
	// See: testdata/docker-compose.yml
	dnsAnswer := DNSAnswer{Domain: host, TTL: 1234}
	switch host {
	case "nginx-1":
		dnsAnswer.Addresses = []net.IP{net.IPv4(10, 254, 249, 3), net.ParseIP("2001:3984:3989::3")}
	case "nginx-2":
		dnsAnswer.Addresses = []net.IP{net.IPv4(10, 254, 249, 4), net.ParseIP("2001:3984:3989::4")}
	}

	return &dnsAnswer, nil
}

// TestIPv4DomainBlockMode 测试 IPv4 域名阻止模式
func TestIPv4DomainBlockMode(t *testing.T) {
	configPath := "../../../testdata/block_domain_v4.yml"
	eventChan := make(chan []byte)

	blockedDomain := "nginx-1"
	blockedIP := "10.254.249.3"
	allowedDomain := "nginx-2"
	allowedIP := "10.254.249.4"

	blockedURL := fmt.Sprintf("http://%s/", blockedDomain)
	allowedURL := fmt.Sprintf("http://%s/", allowedDomain)

	curlResolveOption := fmt.Sprintf("%s:80:%s", blockedDomain, blockedIP)

	auditController := executeAuditOnce(configPath, []string{"curl", "--resolve", curlResolveOption, blockedURL}, eventChan)
	eventData := <-eventChan

	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, eventHeader.EventType)
	body := eventBody.(detectEventIPv4)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, bytes.Equal(net.ParseIP(blockedIP), net.ParseIP(byte2IPv4(body.DstIP))), true)

	err = exec.Command("curl", "--resolve", curlResolveOption, blockedURL).Run()
	assert.NotNil(t, err)

	curlResolveOption = fmt.Sprintf("%s:80:%s", allowedDomain, allowedIP)
	err = exec.Command("curl", "--resolve", "nginx-2:80:10.254.249.4", allowedURL).Run()
	assert.Nil(t, err)

	auditController.manager.mod.Close()
}

// TestIPv6DomainBlockMode 测试 IPv6 域名阻止模式
func TestIPv6DomainBlockMode(t *testing.T) {
	configPath := "../../../testdata/block_domain_v6.yml"
	eventChan := make(chan []byte)

	blockedDomain := "nginx-1"
	blockedIP := "2001:3984:3989::3"
	allowedDomain := "nginx-2"
	allowedIP := "2001:3984:3989::4"

	blockedURL := fmt.Sprintf("http://%s/", blockedDomain)
	allowedURL := fmt.Sprintf("http://%s/", allowedDomain)
	curlResolveOption := fmt.Sprintf("%s:80:%s", blockedDomain, blockedIP)

	auditController := executeAuditOnce(configPath, []string{"curl", "-6", "--resolve", curlResolveOption, blockedURL}, eventChan)
	eventData := <-eventChan

	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV6, eventHeader.EventType)
	body := eventBody.(detectEventIPv6)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, bytes.Equal(net.ParseIP(blockedIP), net.ParseIP(byte2IPv6(body.DstIP))), true)

	err = exec.Command("curl", "--resolve", curlResolveOption, blockedURL).Run()
	assert.NotNil(t, err)

	curlResolveOption = fmt.Sprintf("%s:80:%s", allowedDomain, allowedIP)
	err = exec.Command("curl", "--resolve", curlResolveOption, allowedURL).Run()
	assert.Nil(t, err)

	auditController.manager.mod.Close()
}

// TestIPv4DomainMonitorMode 测试 IPv4 域名监控模式
func TestIPv4DomainMonitorMode(t *testing.T) {
	configPath := "../../../testdata/monitor_domain_v4.yml"
	eventChan := make(chan []byte)

	monitoredDomain := "nginx-1"
	monitoredIP := "10.254.249.3"
	monitoredURL := fmt.Sprintf("http://%s/", monitoredDomain)
	curlResolveOption := fmt.Sprintf("%s:80:%s", monitoredDomain, monitoredIP)

	auditController := executeAuditOnce(configPath, []string{"curl", "--resolve", curlResolveOption, monitoredURL}, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, eventHeader.EventType)

	body := eventBody.(detectEventIPv4)

	assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, monitoredIP, byte2IPv4(body.DstIP))

	auditController.manager.mod.Close()
}

// TestIPv6DomainMonitorMode 测试 IPv6 域名监控模式
func TestIPv6DomainMonitorMode(t *testing.T) {
	configPath := "../../../testdata/monitor_domain_v6.yml"
	eventChan := make(chan []byte)

	monitoredDomain := "nginx-1"
	monitoredIP := "2001:3984:3989:0000:0000:0000:0000:0003"
	monitoredURL := fmt.Sprintf("http://%s/", monitoredDomain)
	curlResolveOption := fmt.Sprintf("%s:80:%s", monitoredDomain, monitoredIP)

	auditController := executeAuditOnce(configPath, []string{"curl", "-6", "--resolve", curlResolveOption, monitoredURL}, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV6, eventHeader.EventType)

	body := eventBody.(detectEventIPv6)

	assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, monitoredIP, byte2IPv6(body.DstIP))

	auditController.manager.mod.Close()
}

// TestIPv6BlockMode 测试 IPv6 阻止模式
func TestIPv6BlockMode(t *testing.T) {
	configPath := "../../../testdata/block_v6.yml"
	eventChan := make(chan []byte)
	blockedAddr := "2001:3984:3989::3"
	allowedAddr := "2001:3984:3989::4"
	auditController := executeAuditOnce(configPath, []string{"curl", "-6", fmt.Sprintf("http://[%s]", blockedAddr)}, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV6, eventHeader.EventType)

	body := eventBody.(detectEventIPv6)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, bytes.Equal(net.ParseIP(blockedAddr), net.ParseIP(byte2IPv6(body.DstIP))), true)

	err = exec.Command("curl", "-6", fmt.Sprintf("http://[%s]", allowedAddr)).Run()
	assert.Nil(t, err)

	err = exec.Command("curl", "-6", fmt.Sprintf("http://[%s]", blockedAddr)).Run()
	assert.NotNil(t, err)

	auditController.manager.mod.Close()
}

// TestIPv4MonitorMode 测试 IPv4 监控模式
func TestIPv4MonitorMode(t *testing.T) {
	configPath := "../../../testdata/monitor_v4.yml"
	eventChan := make(chan []byte)
	monitoredAddr := "10.254.249.3"
	auditController := executeAuditOnce(configPath, []string{"curl", fmt.Sprintf("http://%s", monitoredAddr)}, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, eventHeader.EventType)

	body := eventBody.(detectEventIPv4)

	assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, monitoredAddr, byte2IPv4(body.DstIP))

	auditController.manager.mod.Close()
}

// TestIPv6MonitorMode 测试 IPv6 监控模式
func TestIPv6MonitorMode(t *testing.T) {
	configPath := "../../../testdata/monitor_v6.yml"
	eventChan := make(chan []byte)
	auditController := executeAuditOnce(configPath, []string{"curl", "-6", "http://[2606:2800:220:1:248:1893:25c8:1946]"}, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)
	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV6, eventHeader.EventType)

	body := eventBody.(detectEventIPv6)

	assert.Equal(t, ACTION_MONITOR_STRING, body.ActionResult())
	assert.Equal(t, auditController.command.Process.Pid, int(eventHeader.PID))
	assert.Equal(t, "2606:2800:0220:0001:0248:1893:25c8:1946", byte2IPv6(body.DstIP))

	auditController.manager.mod.Close()
}

// TestCommunicationWithPermittedCommand 测试允许的命令通信
func TestCommunicationWithPermittedCommand(t *testing.T) {
	configPath := "../../../testdata/command_allow.yml"
	configData := loadTestConfig(configPath)
	blockedAddr := "10.254.249.3"
	manager := createTestManager(configData, &DefaultResolver{})

	manager.Attach()
	eventChan := make(chan []byte)
	manager.Start(eventChan)

	err := exec.Command("curl", fmt.Sprintf("http://%s", blockedAddr)).Run()
	assert.Nil(t, err)

	manager.mod.Close()
}

// TestRestrictedCommand 测试限制的命令
func TestRestrictedCommand(t *testing.T) {
	configPath := "../../../testdata/command_deny.yml"
	configData := loadTestConfig(configPath)
	blockedAddr := "10.254.249.3"
	manager := createTestManager(configData, &DefaultResolver{})

	manager.Attach()
	eventChan := make(chan []byte)
	manager.Start(eventChan)

	err := exec.Command("curl", fmt.Sprintf("http://%s", blockedAddr)).Run()
	assert.NotNil(t, err)

	cmd := exec.Command("wget", "-t", "1", fmt.Sprintf("http://%s", blockedAddr), "-O", "/dev/null")
	err = cmd.Run()

	assert.Nil(t, err)

	manager.mod.Close()
}

// TestContainerBlockMode 测试容器阻止模式
func TestContainerBlockMode(t *testing.T) {
	configPath := "../../../testdata/container.yml"
	eventChan := make(chan []byte)
	blockedAddr := "10.254.249.3"
	commands := []string{
		"/bin/bash",
		"-c",
		fmt.Sprintf(
			"/usr/bin/docker run --rm curlimages/curl@sha256:347bf0095334e390673f532456a60bea7070ef63f2ca02168fee46b867a51aa8 http://%s",
			blockedAddr),
	}
	auditController := executeAuditOnce(configPath, commands, eventChan)
	eventData := <-eventChan
	eventHeader, eventBody, err := parseEvent(eventData)

	hostname, err := os.Hostname()
	if err != nil {
		t.Errorf("can not get hostname: %s", err)
	}

	assert.Nil(t, err)

	assert.Equal(t, BLOCKED_IPV4, eventHeader.EventType)

	body := eventBody.(detectEventIPv4)

	assert.Equal(t, ACTION_BLOCKED_STRING, body.ActionResult())
	assert.Equal(t, byte2IPv4(body.DstIP), blockedAddr)
	assert.Equal(t, len(helpers.NodenameToString(eventHeader.Nodename)), 12)
	assert.NotEqual(t, helpers.NodenameToString(eventHeader.Nodename), hostname)

	auditController.manager.mod.Close()
}

// TestContainerHostEventIsolation 测试容器事件隔离
func TestContainerHostEventIsolation(t *testing.T) {
	configPath := "../../../testdata/container.yml"
	blockedAddr := "10.254.249.3"
	timeout := time.After(5 * time.Second)
	doneChan := make(chan bool)

	configData := loadTestConfig(configPath)
	manager := createTestManager(configData, &DefaultResolver{})
	eventChan := make(chan []byte)

	manager.Attach()
	manager.Start(eventChan)

	cmd := exec.Command("curl", fmt.Sprintf("http://%s", blockedAddr))
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	go func() {
		<-eventChan
		doneChan <- true
	}()

	// 如果主机侧触发了事件，且在指定时间内未捕获到事件，则假定仅捕获了容器的事件
	// 在运行其他容器的环境中测试可能不稳定
	// 如果有更好的方法，我会替换它
	select {
	case <-timeout:
		t.Log("OK")
	case <-doneChan:
		t.Fatal("Got host events. Expect capture only container's event.")
	}

	manager.mod.Close()
}

// TestNetworkAuditConfig 测试网络审计配置
func TestNetworkAuditConfig(t *testing.T) {
	configData := config.DefaultConfig()
	configData.RestrictedNetworkConfig.Enable = false
	ctx, cancelFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFunc()

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	assert.Nil(t, RunAudit(ctx, &waitGroup, configData))
}

// executeAuditOnce 执行一次审计测试
func executeAuditOnce(configPath string, execCmd []string, eventChan chan []byte) TestAuditController {
	configData := loadTestConfig(configPath)
	manager := createTestManager(configData, &MockIntegrationDNSResolver{})
	manager.Attach()

	manager.Start(eventChan)

	cmd := exec.Command(execCmd[0], execCmd[1:]...)
	err := cmd.Start()

	if err != nil {
		panic(err)
	}

	cmd.Wait()

	return TestAuditController{
		manager: manager,
		command: cmd,
	}
}

// loadTestConfig 加载测试配置文件
func loadTestConfig(path string) *config.Config {
	conf, err := config.NewConfig(path)
	if err != nil {
		panic(err)
	}
	return conf
}

// createTestManager 创建测试用的网络管理器
func createTestManager(conf *config.Config, dnsResolver DNSResolver) Manager {
	bpfModule, err := setupBPFProgram()
	if err != nil {
		panic(err)
	}

	manager := Manager{
		mod:         bpfModule,
		config:      conf,
		dnsResolver: dnsResolver,
	}

	err = manager.SetConfigToMap()
	if err != nil {
		panic(err)
	}

	return manager
}
