package network

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEventBlockedIPv4_ValidEvent(t *testing.T) {
	body := detectEventIPv4{DstPort: 443, Action: ACTION_BLOCKED, SockType: TCP}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &body)
	result, err := parseEventBlockedIPv4(buf)
	assert.NoError(t, err)
	assert.Equal(t, uint16(443), result.DstPort)
	assert.Equal(t, ACTION_BLOCKED, result.Action)
}

func TestParseEventBlockedIPv4_EmptyBuffer(t *testing.T) {
	buf := new(bytes.Buffer)
	_, err := parseEventBlockedIPv4(buf)
	assert.Error(t, err)
}

