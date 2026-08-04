package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByte2IPv4_Loopback(t *testing.T) {
	result := byte2IPv4([4]byte{127, 0, 0, 1})
	assert.Equal(t, "127.0.0.1", result)
}

func TestByte2IPv4_AllZeros(t *testing.T) {
	result := byte2IPv4([4]byte{0, 0, 0, 0})
	assert.Equal(t, "0.0.0.0", result)
}

func TestByte2IPv6_Loopback(t *testing.T) {
	result := byte2IPv6([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	assert.Equal(t, "0000:0000:0000:0000:0000:0000:0000:0001", result)
}

func TestByte2IPv6_AllZeros(t *testing.T) {
	result := byte2IPv6([16]byte{})
	assert.Equal(t, "0000:0000:0000:0000:0000:0000:0000:0000", result)
}

func TestSockTypeToProtocolName_TCP(t *testing.T) {
	assert.Equal(t, "TCP", sockTypeToProtocolName(TCP))
}

func TestSockTypeToProtocolName_UDP(t *testing.T) {
	assert.Equal(t, "UDP", sockTypeToProtocolName(UDP))
}

func TestSockTypeToProtocolName_Unknown(t *testing.T) {
	assert.Equal(t, "UNKNOWN", sockTypeToProtocolName(99))
}
