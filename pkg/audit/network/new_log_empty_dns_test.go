package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuditLog_EmptyDNSCache(t *testing.T) {
	dnsCache = make(map[string]string)
	header := eventHeader{PID: 1, EventType: EVENT_IPV4}
	var dstIP [DSTIP_V4_LEN]byte
	copy(dstIP[:], []byte{192, 168, 1, 1})
	body := detectEventIPv4{DstIP: dstIP, DstPort: 443, SockType: TCP, Action: ACTION_BLOCKED}
	result := newAuditLog(header, body)
	assert.Equal(t, "", result.Domain)
	assert.Equal(t, "192.168.1.1", result.Addr)
}
