package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"safeguard/pkg/audit/helpers"
	"safeguard/pkg/bpf"
	"safeguard/pkg/config"
	log "safeguard/pkg/log"

	"github.com/miekg/dns"

	"github.com/aquasecurity/libbpfgo"
)

const (
	UPDATE_INTERVAL = 5
	TASK_COMM_LEN   = 16
	NEW_UTS_LEN     = 64
	PADDING_LEN     = 7
	SRCIP_V4_LEN    = 4
	DSTIP_V4_LEN    = 4
	SRCIP_V6_LEN    = 16
	DSTIP_V6_LEN    = 16

	ACTION_MONITOR        uint8 = 0
	ACTION_BLOCKED        uint8 = 1
	ACTION_MONITOR_STRING       = "MONITOR"
	ACTION_BLOCKED_STRING       = "BLOCKED"
	ACTION_UNKNOWN_STRING       = "UNKNOWN"
	MODULE                      = "network"

	BLOCKED_IPV4 int32 = 0
	BLOCKED_IPV6 int32 = 1

	LSM_HOOK_POINT_CONNECT uint8 = 0
	LSM_HOOK_POINT_SENDMSG uint8 = 1

	BPF_OBJECT_IDENTIFIER = "restricted-network"
)

// EventHeader 网络事件头部信息
type EventHeader struct {
	CGroupID      uint64
	PID           uint32
	EventType     int32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [TASK_COMM_LEN]byte
	ParentCommand [TASK_COMM_LEN]byte
	Padding       [PADDING_LEN]byte
}

// DetectEvent 网络事件接口
type DetectEvent interface {
	ActionResult() string
}

// DetectEventIPv4 IPv4 网络事件
type DetectEventIPv4 struct {
	SrcIP        [SRCIP_V4_LEN]byte
	DstIP        [DSTIP_V4_LEN]byte
	DstPort      uint16
	LsmHookPoint uint8
	Action       uint8
	SockType     uint8
}

// DetectEventIPv6 IPv6 网络事件
type DetectEventIPv6 struct {
	SrcIP        [SRCIP_V6_LEN]byte
	DstIP        [DSTIP_V6_LEN]byte
	DstPort      uint16
	LsmHookPoint uint8
	Action       uint8
	SockType     uint8
}

// ActionResult 获取 IPv4 事件的动作结果
func (e DetectEventIPv4) ActionResult() string {
	switch e.Action {
	case ACTION_MONITOR:
		return ACTION_MONITOR_STRING
	case ACTION_BLOCKED:
		return ACTION_BLOCKED_STRING
	default:
		return ACTION_UNKNOWN_STRING
	}
}

// ActionResult 获取 IPv6 事件的动作结果
func (e DetectEventIPv6) ActionResult() string {
	switch e.Action {
	case ACTION_MONITOR:
		return ACTION_MONITOR_STRING
	case ACTION_BLOCKED:
		return ACTION_BLOCKED_STRING
	default:
		return ACTION_UNKNOWN_STRING
	}
}

// initializeBPFModule 初始化 BPF 模块
func initializeBPFModule() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/restricted-network.bpf.o")
	if err != nil {
		return nil, err
	}
	bpfModule, err := libbpfgo.NewModuleFromBuffer(bytecode, BPF_OBJECT_IDENTIFIER)
	if err != nil {
		return nil, err
	}

	if err = bpfModule.BPFLoadObject(); err != nil {
		return nil, err
	}

	return bpfModule, nil
}

// StartNetworkAudit 启动网络审计
func StartNetworkAudit(ctx context.Context, wg *sync.WaitGroup, settings *config.Config) error {
	defer wg.Done()

	if !settings.RestrictedNetworkConfig.Enable {
		log.Info("Network audit is disabled. Shutting down...")
		return nil
	}

	bpfModule, err := initializeBPFModule()
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return err
	}

	controller := NetworkController{
		bpfModule: bpfModule,
		settings:  settings,
		dnsResolver: &DefaultResolver{
			dnsConfig:  dnsConfig,
			dnsClient:  new(dns.Client),
			dnsMessage: new(dns.Msg),
		},
	}

	if err = controller.ConfigureBPFMap(); err != nil {
		log.Fatal(err)
	}

	if controller.settings.EnableDNSProxy() {
		for _, bindAddr := range controller.settings.DNSProxyConfig.BindAddresses {
			go func(addr string) {
				log.Info(fmt.Sprintf("Starting DNS proxy on %s...", addr))
				err := controller.LaunchDNSServer(addr) // 更新为 LaunchDNSServer
				if err != nil {
					log.Fatal(err)
				}
			}(bindAddr)
		}
	} else {
		log.Info("Starting asynchronous DNS resolver...")
		controller.AsyncResolveDNS() // 更新为 AsyncResolveDNS
	}

	if err = controller.AttachBPFPrograms(); err != nil {
		log.Fatal(err)
	}

	log.Info("Starting network audit.")
	eventChan := make(chan []byte)
	controller.Start(eventChan)

	go func() {
		for {
			eventData := <-eventChan
			header, body, err := decodeEvent(eventData)
			if err != nil {
				if err == io.EOF {
					return
				}

				log.Error(err)
				continue
			}

			auditLog := createAuditLog(header, body)
			auditLog.Info()
		}
	}()

	<-ctx.Done()
	controller.Close()
	log.Info("Terminated network audit.")

	return nil
}

// createAuditLog 创建审计日志
func createAuditLog(header EventHeader, body DetectEvent) log.RestrictedNetworkLog {
	var (
		ipAddr   string
		port     uint16
		sockType uint8
	)

	if header.EventType == BLOCKED_IPV6 {
		eventBody := body.(DetectEventIPv6)
		port = eventBody.DstPort
		ipAddr = net.ParseIP(convertBytesToIPv6(eventBody.DstIP)).String()
		sockType = eventBody.SockType
	} else {
		eventBody := body.(DetectEventIPv4)
		port = eventBody.DstPort
		ipAddr = convertBytesToIPv4(eventBody.DstIP)
		sockType = eventBody.SockType
	}

	auditEvent := log.AuditEventLog{
		Module:     MODULE,
		Action:     body.ActionResult(),
		Hostname:   helpers.NodenameToString(header.Nodename),
		PID:        header.PID,
		Comm:       helpers.CommToString(header.Command),
		ParentComm: helpers.CommToString(header.ParentCommand),
	}

	networkLog := log.RestrictedNetworkLog{
		AuditEventLog: auditEvent,
		Addr:          ipAddr,
		Domain:        dnsCache[ipAddr],
		Port:          port,
		Protocol:      sockTypeToProtocolName(sockType),
	}

	return networkLog
}

// decodeEvent 解码网络事件
func decodeEvent(eventData []byte) (EventHeader, DetectEvent, error) {
	dataBuffer := bytes.NewBuffer(eventData)
	header, err := decodeEventHeader(dataBuffer)
	if err != nil {
		return EventHeader{}, nil, err
	}
	if header.EventType == BLOCKED_IPV4 {
		body, err := decodeIPv4Event(dataBuffer)
		if err != nil {
			return EventHeader{}, nil, err
		}
		return header, body, nil
	} else if header.EventType == BLOCKED_IPV6 {
		body, err := decodeIPv6Event(dataBuffer)
		if err != nil {
			return EventHeader{}, nil, err
		}
		return header, body, nil
	}
	return EventHeader{}, nil, fmt.Errorf("unknown event type: %d", header.EventType)
}

// decodeEventHeader 解码事件头部
func decodeEventHeader(dataBuffer *bytes.Buffer) (EventHeader, error) {
	var header EventHeader
	err := binary.Read(dataBuffer, binary.LittleEndian, &header)
	if err != nil {
		return EventHeader{}, err
	}
	return header, nil
}

// decodeIPv4Event 解码 IPv4 事件
func decodeIPv4Event(dataBuffer *bytes.Buffer) (DetectEventIPv4, error) {
	var eventBody DetectEventIPv4
	if err := binary.Read(dataBuffer, binary.LittleEndian, &eventBody); err != nil {
		return DetectEventIPv4{}, err
	}
	return eventBody, nil
}

// decodeIPv6Event 解码 IPv6 事件
func decodeIPv6Event(dataBuffer *bytes.Buffer) (DetectEventIPv6, error) {
	var eventBody DetectEventIPv6
	if err := binary.Read(dataBuffer, binary.LittleEndian, &eventBody); err != nil {
		return DetectEventIPv6{}, err
	}
	return eventBody, nil
}
