package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLsmListContainsBPF_ContainsBPF(t *testing.T) {
	assert.True(t, lsmListContainsBPF("lockdown,bpf"))
}

func TestLsmListContainsBPF_NotContainsBPF(t *testing.T) {
	assert.False(t, lsmListContainsBPF("lockdown,selinux"))
}

func TestLsmListContainsBPF_EmptyString(t *testing.T) {
	assert.False(t, lsmListContainsBPF(""))
}
