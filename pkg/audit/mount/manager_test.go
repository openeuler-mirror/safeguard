package mount

import (
	"bytes"
	"testing"
	"unsafe"

	"safeguard/pkg/config"

	"github.com/stretchr/testify/assert"
)

func Test_ApplyConfigToBPFMap(t *testing.T) {
	testCases := []struct {
		testName      string
		blockedPaths  []string
		expectedValue []byte
	}{
		{
			testName:      "basic_path_test",
			blockedPaths:  []string{"/var/run/docker.sock"},
			expectedValue: []byte{0x2f, 0x76, 0x61, 0x72, 0x2f, 0x72, 0x75, 0x6e, 0x2f, 0x64, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x2e, 0x73, 0x6f, 0x63, 0x6b},
		},
	}

	appConfig := config.DefaultConfig()
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			// 设置测试配置
			appConfig.RestrictedMountConfig.DenySourcePath = testCase.blockedPaths
			auditMgr := initializeTestManager(appConfig)
			defer auditMgr.bpfModule.Close()

			// 获取BPF映射
			deniedPathsMap, err := auditMgr.bpfModule.GetMap(MOUNT_DENY_PATHS_MAP)
			if err != nil {
				t.Fatalf("Failed to access eBPF map '%s', error: %v", MOUNT_DENY_PATHS_MAP, err)
			}

			// 获取映射中的值
			mapKey := uint8(0)
			actualValue, err := deniedPathsMap.GetValue(unsafe.Pointer(&mapKey))
			if err != nil {
				t.Fatalf("Failed to retrieve value from eBPF map '%s', error: %v", MOUNT_DENY_PATHS_MAP, err)
			}

			// 构造期望值（补齐填充字节）
			paddingBytes := bytes.Repeat([]byte{0x00}, MAX_PATH_LENGTH-len(testCase.expectedValue))
			expectedValue := append(testCase.expectedValue, paddingBytes...)

			// 验证结果
			assert.Equal(t, expectedValue, actualValue)
		})
	}
}

func Test_ConfigureModeAndTarget(t *testing.T) {
	testCases := []struct {
		testName      string
		auditMode     string
		auditTarget   string
		expectedValue []byte
	}{
		{
			testName:      "block_container_test",
			auditMode:     "block",
			auditTarget:   "container",
			expectedValue: []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		},
	}

	appConfig := config.DefaultConfig()
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			// 设置测试配置
			appConfig.RestrictedMountConfig.Target = testCase.auditTarget
			appConfig.RestrictedMountConfig.Mode = testCase.auditMode
			auditMgr := initializeTestManager(appConfig)
			defer auditMgr.bpfModule.Close()

			// 获取BPF映射
			configMap, err := auditMgr.bpfModule.GetMap(MOUNT_CONFIG_MAP)
			if err != nil {
				t.Fatalf("Failed to access eBPF map '%s', error: %v", MOUNT_CONFIG_MAP, err)
			}

			// 获取映射中的值
			mapKey := uint8(0)
			actualValue, err := configMap.GetValue(unsafe.Pointer(&mapKey))
			if err != nil {
				t.Fatalf("Failed to retrieve value from eBPF map '%s', error: %v", MOUNT_CONFIG_MAP, err)
			}

			// 验证结果
			assert.Equal(t, testCase.expectedValue, actualValue)
		})
	}
}

func initializeTestManager(conf *config.Config) Manager {
	// 初始化BPF模块
	bpfModule, err := initializeBPFModule()
	if err != nil {
		panic(err)
	}

	// 创建并配置Manager实例
	auditMgr := Manager{
		bpfModule: bpfModule,
		appConfig: conf,
	}

	// 应用配置到BPF映射
	err = auditMgr.ApplyConfigToBPFMap()
	if err != nil {
		panic(err)
	}

	return auditMgr
}
