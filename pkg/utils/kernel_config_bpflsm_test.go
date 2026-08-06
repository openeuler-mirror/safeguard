package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKernelConfigHasBPFLSM_WithBPF(t *testing.T) {
	config := "CONFIG_LSM=\"lockdown,bpf\""
	assert.True(t, kernelConfigHasBPFLSM(config))
}

func TestKernelConfigHasBPFLSM_WithoutBPF(t *testing.T) {
	config := "CONFIG_LSM=\"lockdown,selinux\""
	assert.False(t, kernelConfigHasBPFLSM(config))
}

func TestKernelConfigHasBPFLSM_NoLSMConfig(t *testing.T) {
	assert.False(t, kernelConfigHasBPFLSM("CONFIG_SOMETHING=y"))
}
