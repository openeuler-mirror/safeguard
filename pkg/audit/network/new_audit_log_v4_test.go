package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_IPv4(t *testing.T) {
	initDNSCache()
	header := eventHeader{PID: 100, EventType: BLOCKED_IPV4}
	var dstIP [DSTIP_V4_LEN]byte
	copy(dstIP[:], []byte{10, 0, 0, 1})
	body := detectEventIPv4{DstIP: dstIP, DstPort: 80, SockType: TCP, Action: ACTION_BLOCKED}
	result := newAuditLog(header, body)
	assert.Equal(t, "10.0.0.1", result.Addr)
	assert.Equal(t, uint16(80), result.Port)
	assert.Equal(t, "TCP", result.Protocol)
}
