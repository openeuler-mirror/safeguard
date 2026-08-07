# API 参考

## Controller 包

### Service

`Service` 是 controller 的顶层服务，编排白名单生成流程。

```go
type Service struct {
    Collector model.SnapshotCollector
    Now       func() time.Time
}
```

#### Generate

```go
func (s *Service) Generate() (GenerateResult, error)
```

执行完整的白名单生成流程：采集 → 构建 → 渲染 → 输出。

### Model 包

#### HostSnapshot

```go
type HostSnapshot struct {
    Hostname         string
    CIDRs            []string
    Accounts         []Account
    UIDs             []uint
    GIDs             []uint
    RunningProcesses []string
    ExecutablePaths  []string
    Warnings         []string
}
```

主机快照，包含采集到的所有主机数据。

#### WhitelistModel

```go
type WhitelistModel struct {
    Metadata Metadata
    Network  NetworkWhitelist
    Accounts AccountWhitelist
    Files    FileWhitelist
    Process  ProcessWhitelist
    Warnings []string
}
```

白名单模型，由 `BuildWhitelist` 函数生成。

#### BuildWhitelist

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel
```

将主机快照转换为白名单模型。

### Collector 包

#### SnapshotCollector

```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

数据采集接口，所有采集器必须实现此接口。

### Render 包

#### MarshalConfigYAML

```go
func MarshalConfigYAML(w model.WhitelistModel) ([]byte, error)
```

将白名单模型序列化为 YAML 格式。

#### MarshalReportJSON

```go
func MarshalReportJSON(w model.WhitelistModel) ([]byte, error)
```

将白名单模型序列化为 JSON 报告格式。

## Config 包

### Config

```go
type Config struct {
    Policy                    string
    RestrictedNetworkConfig   RestrictedNetworkConfig
    RestrictedFileAccessConfig RestrictedFileAccessConfig
    RestrictedMountConfig     RestrictedMountConfig
    RestrictedProcessConfig   RestrictedProcessConfig
    DNSProxyConfig            DNSProxyConfig
}
```

safeguard 的完整配置结构。

### DefaultConfig

```go
func DefaultConfig() *Config
```

返回默认配置。

### Validate

```go
func (c *Config) Validate() error
```

验证配置是否合法。

## Log 包

### AuditEventLog

```go
type AuditEventLog struct {
    Module string
    Action string
    PID    uint32
}
```

审计事件日志基础结构。

### RestrictedNetworkLog

网络限制事件日志，包含地址、端口、协议等字段。

### RestrictedFileAccessLog

文件访问限制事件日志，包含文件路径、操作类型等字段。

### RestrictedMountLog

挂载限制事件日志，包含挂载源、目标等字段。

### RestrictedProcessLog

进程限制事件日志，包含命令路径、UID 等字段。
