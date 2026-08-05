package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitDNSCache_Initializes(t *testing.T) {
	dnsCache = nil
	initDNSCache()
	assert.NotNil(t, dnsCache)
}

func TestInitDNSCache_Idempotent(t *testing.T) {
	initDNSCache()
	first := dnsCache
	initDNSCache()
	assert.Equal(t, first, dnsCache)
}
