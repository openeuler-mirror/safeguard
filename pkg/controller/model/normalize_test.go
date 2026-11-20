package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeProcessAllowEntry_UsesExecutableBasename(t *testing.T) {
	result := normalizeProcessAllowEntry(RunningProcess{
		Command:    "laun",
		Executable: "/usr/libexec/at-spi-bus-launcher",
	})
	assert.Equal(t, "at-spi-bus-laun", result)
}

func TestNormalizeProcessAllowEntry_UsesCommandWhenNoExecutable(t *testing.T) {
	result := normalizeProcessAllowEntry(RunningProcess{Command: "bash"})
	assert.Equal(t, "bash", result)
}

func TestNormalizeProcessAllowEntry_PreservesDeletedInComm(t *testing.T) {
	for _, name := range []string{"abc (deleted)", " (deleted)"} {
		result := normalizeProcessAllowEntry(RunningProcess{Command: name})
		assert.Equal(t, name, result)
	}
}

func TestNormalizeProcessAllowEntry_SkipsEmptyCommand(t *testing.T) {
	result := normalizeProcessAllowEntry(RunningProcess{})
	assert.Equal(t, "", result)
}

func TestNormalizeProcessAllowEntry_TruncatesLongNames(t *testing.T) {
	result := normalizeProcessAllowEntry(RunningProcess{
		Executable: "/usr/bin/very-long-process-name-that-exceeds-limit",
	})
	assert.Len(t, result, 15)
}

func TestUniqueStrings_SkipsEmptyAndWhitespace(t *testing.T) {
	result := uniqueStrings([]string{"", "  ", "valid", "valid"})
	assert.Equal(t, []string{"valid"}, result)
}

func TestUniqueStrings_SortsOutput(t *testing.T) {
	result := uniqueStrings([]string{"c", "a", "b"})
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestUniqueUints_SortsAndDeduplicates(t *testing.T) {
	result := uniqueUints([]uint{3, 1, 3, 2})
	assert.Equal(t, []uint{1, 2, 3}, result)
}
