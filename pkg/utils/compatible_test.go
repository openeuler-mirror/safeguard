package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLSMListContainsBPF(t *testing.T) {
	assert.True(t, lsmListContainsBPF("lockdown,capability,landlock,bpf,yama"))
	assert.True(t, lsmListContainsBPF("lockdown, capability, bpf"))
	assert.False(t, lsmListContainsBPF("lockdown,capability,landlock,yama"))
	assert.False(t, lsmListContainsBPF("lockdown,capability,bpfilter"))
}

func TestKernelConfigHasBPFLSM(t *testing.T) {
	assert.True(t, kernelConfigHasBPFLSM(`CONFIG_LSM="lockdown,yama,bpf"`))
	assert.False(t, kernelConfigHasBPFLSM(`CONFIG_LSM="lockdown,yama"`))
	assert.False(t, kernelConfigHasBPFLSM(`CONFIG_BPF_LSM=y`))
}

func TestCmdlineHasBPFLSM(t *testing.T) {
	assert.True(t, cmdlineHasBPFLSM("quiet splash lsm=lockdown,yama,bpf audit=1"))
	assert.False(t, cmdlineHasBPFLSM("quiet splash lsm=lockdown,yama audit=1"))
	assert.False(t, cmdlineHasBPFLSM("quiet splash foo=bpf"))
}
