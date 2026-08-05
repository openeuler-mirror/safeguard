package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToFqdn_AddsDot(t *testing.T) {
	assert.Equal(t, "example.com.", toFqdn("example.com"))
}

func TestToFqdn_KeepsDot(t *testing.T) {
	assert.Equal(t, "example.com.", toFqdn("example.com."))
}
