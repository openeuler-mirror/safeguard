package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadPasswdAccounts_ValidFile(t *testing.T) {
	f, _ := os.CreateTemp("", "passwd")
	defer os.Remove(f.Name())
	f.WriteString("root:x:0:0:root:/root:/bin/bash\nmalformed-line\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
	f.Close()
	accounts, _, _, err := readPasswdAccounts(f.Name())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(accounts))
	assert.Equal(t, uint(0), accounts[0].UID)
	assert.Equal(t, uint(65534), accounts[1].UID)
}

func TestReadPasswdAccounts_BoundsIdentifiersToUint32(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	for _, tc := range []struct {
		ids   string
		valid bool
	}{
		{"1000:1000", true},
		{"4294967295:4294967295", true},
		{"4294967296:1000", false},
		{"1000:4294967296", false},
		{"18446744073709551615:0", false},
		{"0:18446744073709551615", false},
	} {
		t.Run(tc.ids, func(t *testing.T) {
			require.NoError(t, os.WriteFile(path, []byte("user:x:"+tc.ids+":user:/home/user:/bin/sh\n"), 0o600))
			accounts, uids, gids, err := readPasswdAccounts(path)
			require.NoError(t, err)
			if tc.valid {
				require.Len(t, accounts, 1)
				assert.Equal(t, []uint{accounts[0].UID}, uids)
				assert.Equal(t, []uint{accounts[0].GID}, gids)
			} else {
				assert.Empty(t, accounts)
				assert.Empty(t, uids)
				assert.Empty(t, gids)
			}
		})
	}
}
