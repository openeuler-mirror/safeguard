package network

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEventHeader_ValidIPv4(t *testing.T) {
	header := eventHeader{PID: 1234, EventType: BLOCKED_IPV4}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &header)
	result, err := parseEventHeader(buf)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1234), result.PID)
	assert.Equal(t, BLOCKED_IPV4, result.EventType)
}

func TestParseEventHeader_EmptyBuffer(t *testing.T) {
	buf := new(bytes.Buffer)
	_, err := parseEventHeader(buf)
	assert.Error(t, err)
}

