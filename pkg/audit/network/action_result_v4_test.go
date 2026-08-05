package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActionResult_IPv4Monitor(t *testing.T) {
	e := detectEventIPv4{Action: ACTION_MONITOR}
	assert.Equal(t, ACTION_MONITOR_STRING, e.ActionResult())
}

func TestActionResult_IPv4Blocked(t *testing.T) {
	e := detectEventIPv4{Action: ACTION_BLOCKED}
	assert.Equal(t, ACTION_BLOCKED_STRING, e.ActionResult())
}

func TestActionResult_IPv4Unknown(t *testing.T) {
	e := detectEventIPv4{Action: 99}
	assert.Equal(t, ACTION_UNKNOWN_STRING, e.ActionResult())
}
