package network

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEvent_IPv4Event(t *testing.T) {
	header := eventHeader{PID: 100, EventType: BLOCKED_IPV4}
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
	header := eventHeader{PID: 200, EventType: BLOCKED_IPV6}
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

func TestParseEventUnknownType(t *testing.T) {
	for _, eventType := range []int32{-1, 2, 999} {
		buf := new(bytes.Buffer)
		assert.NoError(t, binary.Write(buf, binary.LittleEndian, &eventHeader{EventType: eventType, PID: 42}))
		assert.NoError(t, binary.Write(buf, binary.LittleEndian, &detectEventIPv4{Action: ACTION_BLOCKED}))
		_, body, err := parseEvent(buf.Bytes())
		assert.ErrorContains(t, err, "unknown network event type")
		assert.Nil(t, body)
	}
}

func TestParseEventMissingBody(t *testing.T) {
	for _, kind := range []int32{BLOCKED_IPV4, BLOCKED_IPV6} {
		buf := new(bytes.Buffer)
		assert.NoError(t, binary.Write(buf, binary.LittleEndian, &eventHeader{EventType: kind}))
		_, _, err := parseEvent(buf.Bytes())
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}
