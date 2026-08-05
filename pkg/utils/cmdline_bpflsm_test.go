package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCmdlineHasBPFLSM_WithBPF(t *testing.T) {
	cmdline := "BOOT_IMAGE=/vmlinuz root=/dev/sda1 lsm=lockdown,bpf"
	assert.True(t, cmdlineHasBPFLSM(cmdline))
}

func TestCmdlineHasBPFLSM_WithoutBPF(t *testing.T) {
	cmdline := "BOOT_IMAGE=/vmlinuz root=/dev/sda1 lsm=lockdown,selinux"
	assert.False(t, cmdlineHasBPFLSM(cmdline))
}

func TestCmdlineHasBPFLSM_NoLSMParam(t *testing.T) {
	cmdline := "BOOT_IMAGE=/vmlinuz root=/dev/sda1"
	assert.False(t, cmdlineHasBPFLSM(cmdline))
}
