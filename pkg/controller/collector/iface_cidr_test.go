package collector
import (
	"net"
	"testing"
	"github.com/stretchr/testify/assert"
)
func TestInterfaceAddressToCIDR_IPNet(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.1/32")
	cidr, ok := interfaceAddressToCIDR(ipNet)
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.1/32", cidr)
}
func TestInterfaceAddressToCIDR_IPAddr(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("::1")}
	cidr, ok := interfaceAddressToCIDR(addr)
	assert.True(t, ok)
	assert.Contains(t, cidr, "/128")
}
func TestInterfaceAddressToCIDR_UnknownType(t *testing.T) {
	_, ok := interfaceAddressToCIDR(&net.TCPAddr{})
	assert.False(t, ok)
}
