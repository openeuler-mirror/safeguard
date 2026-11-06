package helpers

import (
	"errors"
	"testing"
	"unsafe"

	"culinux/pkg/bpf"

	"github.com/aquasecurity/libbpfgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name:   "embedded null terminates the string",
			input:  [65]byte{0x61, 0x00, 0x62, 0x00, 0x63},
			expect: "a",
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
			name:   "embedded null terminates the string",
			input:  [16]byte{0x61, 0x00, 0x62},
			expect: "a",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, CommToString(test.input), test.expect)
		})
	}
}

type configMapProbe struct {
	keySize, valueSize int
	key                uint32
	value              []byte
	err                error
}

func (m *configMapProbe) KeySize() int   { return m.keySize }
func (m *configMapProbe) ValueSize() int { return m.valueSize }
func (m *configMapProbe) Update(key, value unsafe.Pointer) error {
	m.key = *(*uint32)(key)
	m.value = append([]byte(nil), unsafe.Slice((*byte)(value), m.valueSize)...)
	return m.err
}

func TestAuditConfigMapKeyWidth(t *testing.T) {
	for _, tc := range []struct {
		object, name string
		valueSize    int
	}{
		{"network", "network_safeguard_config_map", 24}, {"file", "fileopen_safeguard_config_map", 12},
		{"mount", "mount_safeguard_config_map", 8}, {"process", "process_safeguard_config_map", 16},
	} {
		data, err := bpf.EmbedFS.ReadFile("bytecode/restricted-" + tc.object + ".bpf.o")
		require.NoError(t, err)
		module, err := libbpfgo.NewModuleFromBuffer(data, "schema_test")
		require.NoError(t, err)
		m, err := module.GetMap(tc.name)
		require.NoError(t, err)
		require.Equal(t, 4, m.KeySize())
		require.Equal(t, tc.valueSize, m.ValueSize())
		module.Close()
		injected := errors.New("update failed")
		fake := &configMapProbe{keySize: 4, valueSize: tc.valueSize, err: injected}
		payload := []byte("abcdefghijklmnopqrstuvwx")[:tc.valueSize]
		require.ErrorIs(t, UpdateConfigMap(fake, payload), injected)
		require.Zero(t, fake.key)
		require.Equal(t, payload, fake.value)
		err = UpdateConfigMap(fake, payload[:len(payload)-1])
		require.Error(t, err)
		require.NotErrorIs(t, err, injected)
	}
}

func TestNetworkPresenceMapValueWidth(t *testing.T) {
	data, err := bpf.EmbedFS.ReadFile("bytecode/restricted-network.bpf.o")
	require.NoError(t, err)
	module, err := libbpfgo.NewModuleFromBuffer(data, "presence_schema")
	require.NoError(t, err)
	defer module.Close()
	for _, name := range []string{"allowed_command_list", "denied_command_list", "allowed_uid_list", "denied_uid_list", "allowed_gid_list", "denied_gid_list"} {
		m, err := module.GetMap(name)
		require.NoError(t, err)
		require.Equal(t, 4, m.ValueSize())
		injected := errors.New("update failed")
		fake := &configMapProbe{keySize: m.KeySize(), valueSize: m.ValueSize(), err: injected}
		key := make([]byte, m.KeySize())
		require.ErrorIs(t, UpdateUint32MapValue(fake, key), injected)
		require.Equal(t, []byte{0, 0, 0, 0}, fake.value)
		err = UpdateUint32MapValue(fake, key[:len(key)-1])
		require.Error(t, err)
		require.NotErrorIs(t, err, injected)
	}
	lpm, err := module.GetMap("allowed_v4_cidr_list")
	require.NoError(t, err)
	require.Equal(t, 1, lpm.ValueSize())
}

func TestAuditStringBytes(t *testing.T) {
	var comm [16]byte
	copy(comm[:], []byte("进程"))
	require.Equal(t, "进程", CommToString(comm))
	var host [65]byte
	copy(host[:], []byte("主机.example"))
	require.Equal(t, "主机.example", NodenameToString(host))
	comm = [16]byte{0xc3, 0xa9, 0, 0xff}
	require.Equal(t, "é", CommToString(comm))
	host = [65]byte{0xc3, 0xa9, 0, 0xff}
	require.Equal(t, "é", NodenameToString(host))
}
