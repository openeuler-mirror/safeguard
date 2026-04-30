package utils

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/coreos/go-semver/semver"
)

const supportKernelVersion = "5.8.0"
const btfFile = "/sys/kernel/btf/vmlinux"
const securityLSMFile = "/sys/kernel/security/lsm"

func isLinux() bool {
	return runtime.GOOS == "linux"
}

func currentKernelVersion() (*semver.Version, error) {
	buf, err := rawKernelVersion()
	if err != nil {
		return nil, err
	}

	ver, err := parseKernelVersion(buf)
	if err != nil {
		return nil, err
	}

	return ver, nil
}

func parseKernelVersion(buf []byte) (*semver.Version, error) {
	// Formats like 5.11.0-34-generic.
	// Only keep the major, minor, and patch version.
	parts := bytes.Split(buf, []byte("-"))
	s := strings.TrimSpace(string(parts[0]))

	ver, err := semver.NewVersion(s)
	if err != nil {
		return nil, err
	}

	return ver, nil
}

func hasSupportKernelVersion() error {
	supportVersion := semver.New(supportKernelVersion)
	version, err := currentKernelVersion()
	if err != nil {
		return err
	}

	if version.LessThan(*supportVersion) {
		return fmt.Errorf("current kernel version not supported. minimum supported kernel version is %v", supportKernelVersion)
	}

	return nil
}

func hasBTF() error {
	f, err := os.Open(btfFile)

	if err != nil {
		// lint:ignore ST1005
		return fmt.Errorf("Current kernel is not supported for BTF. Requires kernel with `CONFIG_DEBUG_INFO_BTF` enabled")
	}

	defer f.Close()

	return nil
}

func rawKernelVersion() ([]byte, error) {
	f, err := os.Open("/proc/sys/kernel/osrelease")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func readKernelConfig() (string, error) {
	buf, err := rawKernelVersion()
	if err != nil {
		return "", err
	}

	configPath := fmt.Sprintf("/boot/config-%s", strings.Replace(string(buf), "\n", "", -1))
	f, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	kernelConfig, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(kernelConfig), err
}

func readCmdline() (string, error) {
	f, err := os.Open("/proc/cmdline")
	if err != nil {
		return "", err
	}

	defer f.Close()

	cmdline, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(cmdline), err
}

func readSecurityLSM() (string, error) {
	f, err := os.Open(securityLSMFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	lsm, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(lsm), nil
}

func lsmListContainsBPF(lsmList string) bool {
	for _, lsm := range strings.Split(lsmList, ",") {
		if strings.TrimSpace(lsm) == "bpf" {
			return true
		}
	}
	return false
}

func kernelConfigHasBPFLSM(kernelConfig string) bool {
	re := regexp.MustCompile(`CONFIG_LSM="([^"]*)"`)
	matches := re.FindStringSubmatch(kernelConfig)
	return len(matches) > 0 && lsmListContainsBPF(matches[1])
}

func cmdlineHasBPFLSM(cmdline string) bool {
	for _, field := range strings.Fields(cmdline) {
		if strings.HasPrefix(field, "lsm=") {
			return lsmListContainsBPF(strings.TrimPrefix(field, "lsm="))
		}
	}
	return false
}

func hasBPFLSM() error {
	if activeLSM, err := readSecurityLSM(); err == nil && lsmListContainsBPF(activeLSM) {
		return nil
	}

	if cmdline, err := readCmdline(); err == nil && cmdlineHasBPFLSM(cmdline) {
		return nil
	}

	if kernelConfig, err := readKernelConfig(); err == nil && kernelConfigHasBPFLSM(kernelConfig) {
		return nil
	}

	return fmt.Errorf("BPF LSM is not enabled. Enable bpf in the active LSM list, CONFIG_LSM, or boot lsm= parameters")
}

func AmIRootUser() bool {
	return os.Geteuid() == 0
}

func IsCompatible() error {
	if !isLinux() {
		return errors.New("required to run on Linux")
	}

	if err := hasSupportKernelVersion(); err != nil {
		return err
	}

	if err := hasBTF(); err != nil {
		return err
	}

	if err := hasBPFLSM(); err != nil {
		return err
	}

	return nil
}
