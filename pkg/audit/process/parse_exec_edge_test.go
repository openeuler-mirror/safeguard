package process

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcessExecAction(t *testing.T) {
	for _, tc := range []struct {
		action uint8
		want   string
	}{
		{ACTION_MONITOR, "MONITOR"},
		{ACTION_BLOCK, "BLOCKED"},
		{2, "UNKNOWN"},
		{255, "UNKNOWN"},
	} {
		assert.Equal(t, tc.want, processExecAction(tc.action))
	}
}

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
