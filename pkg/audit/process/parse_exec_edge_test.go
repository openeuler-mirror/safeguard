package process

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseExecEvent_ShortBytes(t *testing.T) {
	_, err := parseExecEvent([]byte{0x01})
	assert.Error(t, err)
}

func TestParseExecEvent_ValidEvent(t *testing.T) {
	var event processExecEvent
	event.PID = 100
	event.PPID = 1
	event.UID = 0
	event.Action = 1
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &event)
	result, err := parseExecEvent(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
}
