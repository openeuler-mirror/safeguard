package fileaccess

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEvent_ValidEvent(t *testing.T) {
	var event auditLog
	event.PID = 1234
	event.Ret = 0
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &event)
	result, err := parseEvent(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, uint32(1234), result.PID)
}

func TestParseEvent_ShortBytes(t *testing.T) {
	_, err := parseEvent([]byte{0x01, 0x02})
	assert.Error(t, err)
}

