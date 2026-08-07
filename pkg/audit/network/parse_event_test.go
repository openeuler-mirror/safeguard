package network

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEvent_IPv4Event(t *testing.T) {
	header := eventHeader{PID: 100, EventType: EVENT_IPV4}
	body := detectEventIPv4{DstPort: 443, Action: ACTION_BLOCKED}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &header)
	binary.Write(buf, binary.LittleEndian, &body)
	h, b, err := parseEvent(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), h.PID)
	_, ok := b.(detectEventIPv4)
	assert.True(t, ok)
}

func TestParseEvent_IPv6Event(t *testing.T) {
	header := eventHeader{PID: 200, EventType: EVENT_IPV6}
	body := detectEventIPv6{DstPort: 80, Action: ACTION_MONITOR}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &header)
	binary.Write(buf, binary.LittleEndian, &body)
	h, b, err := parseEvent(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, uint32(200), h.PID)
	_, ok := b.(detectEventIPv6)
	assert.True(t, ok)
}

func TestParseEvent_EmptyBytes(t *testing.T) {
	_, _, err := parseEvent([]byte{})
	assert.Error(t, err)
}

