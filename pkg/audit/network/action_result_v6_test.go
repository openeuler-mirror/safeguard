package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActionResult_IPv6Monitor(t *testing.T) {
	e := detectEventIPv6{Action: ACTION_MONITOR}
	assert.Equal(t, ACTION_MONITOR_STRING, e.ActionResult())
}

func TestActionResult_IPv6Blocked(t *testing.T) {
	e := detectEventIPv6{Action: ACTION_BLOCKED}
	assert.Equal(t, ACTION_BLOCKED_STRING, e.ActionResult())
}

func TestActionResult_IPv6Unknown(t *testing.T) {
	e := detectEventIPv6{Action: 99}
	assert.Equal(t, ACTION_UNKNOWN_STRING, e.ActionResult())
}
