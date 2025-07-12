package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConvertToFQDN 测试将域名转换为 FQDN 格式
func TestConvertToFQDN(t *testing.T) {
	testCases := []struct {
		testName string
		domain   string
		expected string
	}{
		{
			testName: "example.com -> example.com.",
			domain:   "example.com",
			expected: "example.com.",
		},
		{
			testName: "example.com. -> example.com.",
			domain:   "example.com.",
			expected: "example.com.",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			result := ConvertToFQDN(testCase.domain)
			assert.Equal(t, testCase.expected, result)
		})
	}
}
