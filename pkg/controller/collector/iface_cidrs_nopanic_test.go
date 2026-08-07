package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCollectInterfaceCIDRs_DoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		collectInterfaceCIDRs()
	})
}
