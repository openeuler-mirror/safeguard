package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func bytesToNode(b [65]byte) [65]byte { return b }
func bytesToComm(b [16]byte) [16]byte { return b }

func TestNodenameToString(t *testing.T) {
	tests := []struct {
		name   string
		input  [65]byte
		expect string
	}{
		{
			name:   "normal string (ubuntu)",
			input:  [65]byte{0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x00},
			expect: "ubuntu",
		},
		{
			name:   "empty array returns empty string",
			input:  [65]byte{},
			expect: "",
		},
		{
			name:   "full-length 65-byte string",
			input:  bytesToNode([65]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2d}),
			expect: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
		},
		{
			name:   "embedded null byte is skipped",
			input:  [65]byte{0x61, 0x00, 0x62, 0x00, 0x63},
			expect: "abc",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, NodenameToString(test.input), test.expect)
		})
	}
}

func TestCommToString(t *testing.T) {
	tests := []struct {
		name   string
		input  [16]byte
		expect string
	}{
		{
			name:   "normal string (curl)",
			input:  [16]byte{0x63, 0x75, 0x72, 0x6c, 0x00},
			expect: "curl",
		},
		{
			name:   "empty array returns empty string",
			input:  [16]byte{},
			expect: "",
		},
		{
			name:   "full-length 16-byte string",
			input:  bytesToComm([16]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70}),
			expect: "abcdefghijklmnop",
		},
		{
			name:   "embedded null byte is skipped",
			input:  [16]byte{0x61, 0x00, 0x62},
			expect: "ab",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, CommToString(test.input), test.expect)
		})
	}
}
