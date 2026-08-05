package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_IPv6(t *testing.T) {
	initDNSCache()
	header := eventHeader{PID: 200, EventType: BLOCKED_IPV6}
	var dstIP [DSTIP_V6_LEN]byte
	dstIP[15] = 1
	body := detectEventIPv6{DstIP: dstIP, DstPort: 443, SockType: TCP, Action: ACTION_MONITOR}
	result := newAuditLog(header, body)
	assert.Contains(t, result.Addr, "::1")
	assert.Equal(t, uint16(443), result.Port)
	assert.Equal(t, "TCP", result.Protocol)
}
