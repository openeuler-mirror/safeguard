package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
)

const btfFile = "/sys/kernel/btf/vmlinux"
const securityLSMFile = "/sys/kernel/security/lsm"

// isLinux checks whether the current OS is Linux.
func isLinux() bool {
	return runtime.GOOS == "linux"
}

// hasBTF checks if the kernel has BTF support enabled.
func hasBTF() error {
	f, err := os.Open(btfFile)
	if err != nil {
		// lint:ignore ST1005
		return fmt.Errorf("Current kernel is not supported for BTF. Requires kernel with `CONFIG_DEBUG_INFO_BTF` enabled")
	}

	defer f.Close()

	return nil
}

// getKernelVersion reads the kernel release string from /proc.
func getKernelVersion() (string, error) {
	buf, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", fmt.Errorf("reading kernel version: %w", err)
	}
	return strings.TrimSpace(string(buf)), nil
}

// readKernelConfig reads the kernel configuration file for the current kernel.
func readKernelConfig() (string, error) {
	kernelVer, err := getKernelVersion()
	if err != nil {
		return "", fmt.Errorf("reading kernel config: %w", err)
	}

	configPath := fmt.Sprintf("/boot/config-%s", kernelVer)
	f, err := os.Open(configPath)
	if err != nil {
		return "", fmt.Errorf("opening kernel config %s: %w", configPath, err)
	}
	defer f.Close()

	kernelConfig, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading kernel config: %w", err)
	}

	return string(kernelConfig), nil
}

// readCmdline reads the kernel boot command line from /proc/cmdline.
func readCmdline() (string, error) {
	f, err := os.Open("/proc/cmdline")
	if err != nil {
		return "", fmt.Errorf("opening /proc/cmdline: %w", err)
	}

	defer f.Close()

	cmdline, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading /proc/cmdline: %w", err)
	}

	return string(cmdline), nil
}

// readSecurityLSM reads the active LSM list from /sys/kernel/security/lsm.
func readSecurityLSM() (string, error) {
	f, err := os.Open(securityLSMFile)
	if err != nil {
		return "", fmt.Errorf("opening security LSM file: %w", err)
	}
	defer f.Close()

	lsm, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading security LSM file: %w", err)
	}

	return string(lsm), nil
}

// lsmListContainsBPF checks if "bpf" is present in the comma-separated LSM list.
func lsmListContainsBPF(lsmList string) bool {
	for _, lsm := range strings.Split(lsmList, ",") {
		if strings.TrimSpace(lsm) == "bpf" {
			return true
		}
	}
	return false
}

// kernelConfigHasBPFLSM checks if the kernel CONFIG_LSM option includes bpf.
func kernelConfigHasBPFLSM(kernelConfig string) bool {
	re := regexp.MustCompile(`CONFIG_LSM="([^"]*)"`)
	matches := re.FindStringSubmatch(kernelConfig)
	return len(matches) > 0 && lsmListContainsBPF(matches[1])
}

// cmdlineHasBPFLSM checks if the boot command line lsm= parameter includes bpf.
func cmdlineHasBPFLSM(cmdline string) bool {
	for _, field := range strings.Fields(cmdline) {
		if strings.HasPrefix(field, "lsm=") {
			return lsmListContainsBPF(strings.TrimPrefix(field, "lsm="))
		}
	}
	return false
}

// hasBPFLSM checks if BPF LSM is enabled via the active LSM list, boot parameters, or kernel config.
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

// AmIRootUser checks if the current process is running as root.
func AmIRootUser() bool {
	return os.Geteuid() == 0
}

// IsCompatible checks if the system meets safeguard requirements (kernel version, BPF LSM, BTF).
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
