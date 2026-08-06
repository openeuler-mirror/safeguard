package mount

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEvent_ValidEvent(t *testing.T) {
	var event auditLog
	event.PID = 5678
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &event)
	result, err := parseEvent(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, uint32(5678), result.PID)
}

func TestParseEvent_EmptyBytes(t *testing.T) {
	_, err := parseEvent([]byte{})
	assert.Error(t, err)
}

