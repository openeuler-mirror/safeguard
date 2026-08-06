package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCollectInterfaceCIDRs_ReturnsResultOrError(t *testing.T) {
	// Just verify it doesn't panic on a real system
	cidrs, err := collectInterfaceCIDRs()
	if err != nil {
		assert.Empty(t, cidrs)
	} else {
		// On a real system, should have at least loopback
		assert.NotNil(t, cidrs)
	}
}
