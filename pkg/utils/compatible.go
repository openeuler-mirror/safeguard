package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strings"
)

const btfFile = "/sys/kernel/btf/vmlinux"
const securityLSMFile = "/sys/kernel/security/lsm"

func isLinux() bool {
	return runtime.GOOS == "linux"
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

func getKernelVersion() (string, error) {
	buf, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

func readKernelConfig() (string, error) {
	kernelVer, err := getKernelVersion()
	if err != nil {
		return "", err
	}

	configPath := fmt.Sprintf("/boot/config-%s", kernelVer)
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

	// 内核版本检查已移除 - 自编译内核版本格式可能不标准
	// eBPF程序加载时会自然失败并给出错误信息

	if err := hasBTF(); err != nil {
		return err
	}

	if err := hasBPFLSM(); err != nil {
		return err
	}

	return nil
}
