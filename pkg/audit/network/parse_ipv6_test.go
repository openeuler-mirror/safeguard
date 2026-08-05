package network

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEventBlockedIPv6_ValidEvent(t *testing.T) {
	body := detectEventIPv6{DstPort: 80, Action: ACTION_MONITOR, SockType: UDP}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &body)
	result, err := parseEventBlockedIPv6(buf)
	assert.NoError(t, err)
	assert.Equal(t, uint16(80), result.DstPort)
	assert.Equal(t, ACTION_MONITOR, result.Action)
}

func TestParseEventBlockedIPv6_EmptyBuffer(t *testing.T) {
	buf := new(bytes.Buffer)
	_, err := parseEventBlockedIPv6(buf)
	assert.Error(t, err)
}

