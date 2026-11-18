package utils

import (
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadKernelConfigPaths(t *testing.T) {
	dir := t.TempDir()
	plain, compressed := filepath.Join(dir, "config"), filepath.Join(dir, "config.gz")
	f, err := os.Create(compressed)
	require.NoError(t, err)
	w := gzip.NewWriter(f)
	_, err = w.Write([]byte("compressed"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
	value, err := readKernelConfigPaths(plain, compressed)
	assert.NoError(t, err)
	assert.Equal(t, "compressed", value)
	require.NoError(t, os.WriteFile(plain, []byte("plain"), 0600))
	value, err = readKernelConfigPaths(plain, compressed)
	assert.NoError(t, err)
	assert.Equal(t, "plain", value)
	require.NoError(t, os.Remove(plain))
	require.NoError(t, os.WriteFile(compressed, []byte("broken"), 0600))
	_, err = readKernelConfigPaths(plain, compressed)
	assert.ErrorContains(t, err, compressed)
}

func TestCheckBPFLSMActiveListIsAuthoritative(t *testing.T) {
	for _, tc := range []struct {
		active   string
		err      error
		want     bool
		fallback bool
	}{
		{"capability,bpf", nil, true, false},
		{"capability,selinux", nil, false, false},
		{"", errors.New("unreadable"), true, true},
	} {
		calls := 0
		readActive := func() (string, error) { return tc.active, tc.err }
		readFallback := func() (string, error) { calls++; return "lsm=bpf", nil }
		err := checkBPFLSM(readActive, readFallback, readFallback)
		assert.Equal(t, tc.want, err == nil)
		assert.Equal(t, tc.fallback, calls > 0)
	}
	unavailable := func() (string, error) { return "", errors.New("unavailable") }
	bootWithoutOverride := func() (string, error) { return "quiet splash", nil }
	configWithBPF := func() (string, error) { return `CONFIG_LSM="capability,bpf"`, nil }
	assert.NoError(t, checkBPFLSM(unavailable, bootWithoutOverride, configWithBPF))
	assert.Error(t, checkBPFLSM(unavailable, unavailable, unavailable))
}

func TestCheckBPFLSMBootOverride(t *testing.T) {
	unavailable := func() (string, error) { return "", errors.New("unavailable") }
	config := func() (string, error) { return `CONFIG_LSM="capability,bpf"`, nil }
	for _, tc := range []struct {
		cmdline string
		want    bool
	}{
		{"quiet lsm=capability", false},
		{"quiet lsm=capability,bpf", true},
		{"lsm=bpf lsm=capability", false},
		{"lsm=capability lsm=bpf", true},
		{"quiet", true},
		{`lsm="capability,bpf"`, true},
		{`"lsm=capability,bpf"`, true},
		{`lsm="capability, bpf"`, false},
		{`lsm=capability -- lsm=bpf`, false},
		{`quiet -- lsm=capability`, true},
		{`other="value lsm=bpf" lsm=capability`, false},
		{`other="value lsm=capability"`, true},
	} {
		readBoot := func() (string, error) { return tc.cmdline, nil }
		err := checkBPFLSM(unavailable, readBoot, config)
		assert.Equal(t, tc.want, err == nil, tc.cmdline)
	}
}

func TestCheckBPFLSMDisabledKernelConfig(t *testing.T) {
	unavailable := func() (string, error) { return "", errors.New("unavailable") }
	for _, boot := range []string{"quiet", "lsm=capability,bpf"} {
		for _, disabled := range []string{"# CONFIG_BPF_LSM is not set", "CONFIG_BPF_LSM=n"} {
			readBoot := func() (string, error) { return boot, nil }
			readConfig := func() (string, error) { return "CONFIG_LSM=\"bpf\"\n" + disabled, nil }
			assert.ErrorContains(t, checkBPFLSM(unavailable, readBoot, readConfig), "disabled")
		}
	}
	boot := func() (string, error) { return "lsm=bpf", nil }
	assert.NoError(t, checkBPFLSM(unavailable, boot, unavailable))
	active := func() (string, error) { return "capability,bpf", nil }
	disabled := func() (string, error) { return "CONFIG_BPF_LSM=n", nil }
	assert.NoError(t, checkBPFLSM(active, boot, disabled))
}

func TestLSMListContainsBPF(t *testing.T) {
	assert.True(t, lsmListContainsBPF("lockdown,capability,landlock,bpf,yama"))
	assert.True(t, lsmListContainsBPF("lockdown, capability, bpf"))
	assert.True(t, lsmListContainsBPF("bpf"))
	assert.False(t, lsmListContainsBPF("lockdown,capability,landlock,yama"))
	assert.False(t, lsmListContainsBPF("lockdown,capability,bpfilter"))
	assert.False(t, lsmListContainsBPF(""))
}

func TestKernelConfigHasBPFLSM(t *testing.T) {
	assert.True(t, kernelConfigHasBPFLSM(`CONFIG_LSM="lockdown,yama,bpf"`))
	assert.True(t, kernelConfigHasBPFLSM(`CONFIG_LSM="bpf"`))
	assert.False(t, kernelConfigHasBPFLSM(`CONFIG_LSM="lockdown,yama"`))
	assert.False(t, kernelConfigHasBPFLSM(`CONFIG_BPF_LSM=y`))
	assert.False(t, kernelConfigHasBPFLSM(""))
}

func TestKernelConfigLSMLineMustBeExact(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   bool
	}{
		{"CONFIG_LSM=\"capability,bpf\"\r\n", true},
		{"# CONFIG_LSM=\"bpf\"\n", false},
		{"OTHER_CONFIG_LSM=\"bpf\"\n", false},
		{"CONFIG_LSM=\"capability, bpf\"\n", false},
		{"CONFIG_LSM=\"bpf\" # comment\n", false},
		{"CONFIG_LSM=\"invalid\",bpf\"\n", false},
	} {
		assert.Equal(t, tc.want, kernelConfigHasBPFLSM(tc.config), tc.config)
	}
}

func TestCmdlineHasBPFLSM(t *testing.T) {
	assert.True(t, cmdlineHasBPFLSM("quiet splash lsm=lockdown,yama,bpf audit=1"))
	assert.True(t, cmdlineHasBPFLSM("lsm=bpf"))
	assert.False(t, cmdlineHasBPFLSM("quiet splash lsm=lockdown,yama audit=1"))
	assert.False(t, cmdlineHasBPFLSM("quiet splash foo=bpf"))
	assert.False(t, cmdlineHasBPFLSM(""))
}
