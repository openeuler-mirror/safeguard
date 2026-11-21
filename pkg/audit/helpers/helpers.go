package helpers

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// NormalizeRulePath removes trailing separators while preserving the root path.
func NormalizeRulePath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" && path != "" {
		return "/"
	}
	return trimmed
}

func CommToString(commBytes [16]byte) string {
	return cStringBytes(commBytes[:])
}

func NodenameToString(bytes [65]byte) string {
	return cStringBytes(bytes[:])
}

func cStringBytes(input []byte) string {
	end := bytes.IndexByte(input, 0)
	if end < 0 {
		end = len(input)
	}
	return string(input[:end])
}

// HostMountNamespace returns PID 1's mount namespace after checking its PID namespace.
func HostMountNamespace() (uint32, error) {
	return hostMountNamespace(func(path string) (uint64, error) {
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, fmt.Errorf("namespace stat unavailable for %s", path)
		}
		return stat.Ino, nil
	})
}

func hostMountNamespace(inode func(string) (uint64, error)) (uint32, error) {
	pid, err := inode("/proc/1/ns/pid")
	if err != nil {
		return 0, fmt.Errorf("read PID 1 pid namespace: %w", err)
	}
	if pid != 0xeffffffc {
		return 0, fmt.Errorf("PID 1 is not in the initial PID namespace")
	}
	mount, err := inode("/proc/1/ns/mnt")
	if err != nil {
		return 0, fmt.Errorf("read PID 1 mount namespace: %w", err)
	}
	if mount == 0 || mount > 1<<32-1 {
		return 0, fmt.Errorf("invalid mount namespace inode %d", mount)
	}
	return uint32(mount), nil
}

// UpdateConfigMap writes the u32 zero key used by audit configuration maps.
func UpdateConfigMap(m interface {
	KeySize() int
	ValueSize() int
	Update(unsafe.Pointer, unsafe.Pointer) error
}, value []byte) error {
	if m.KeySize() != 4 || len(value) != m.ValueSize() || len(value) == 0 {
		return fmt.Errorf("invalid configuration map dimensions: key=%d value=%d payload=%d", m.KeySize(), m.ValueSize(), len(value))
	}
	var key uint32
	return m.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
}

// UpdateUint32MapValue writes a zero u32 value to a keyed presence map.
func UpdateUint32MapValue(m interface {
	KeySize() int
	ValueSize() int
	Update(unsafe.Pointer, unsafe.Pointer) error
}, key []byte) error {
	if len(key) == 0 || len(key) != m.KeySize() || m.ValueSize() != 4 {
		return fmt.Errorf("invalid presence map dimensions: key=%d payload=%d value=%d", m.KeySize(), len(key), m.ValueSize())
	}
	var value uint32
	return m.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
}
