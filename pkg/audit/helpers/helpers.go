package helpers

import (
	"fmt"
	"unsafe"
)

func CommToString(commBytes [16]byte) string {
	var s string
	for _, b := range commBytes {
		if b != 0x00 {
			s += string(b)
		}
	}
	return s
}

func NodenameToString(bytes [65]byte) string {
	var s string
	for _, b := range bytes {
		if b != 0x00 {
			s += string(b)
		}
	}
	return s
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
