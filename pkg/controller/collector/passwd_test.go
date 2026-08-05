package collector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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

