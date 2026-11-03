# API 参考

## 审计运行生命周期

```shell
sudo safeguard --config /etc/safeguard/safeguard.yaml --startup-timeout 30s --shutdown-timeout 10s
# 所有启用模块的事件缓冲区启动后：All configured audit modules started.
# Ctrl-C（SIGINT）且正常完成退出：退出码 0。
safeguard --config /missing/safeguard.yaml
# 配置读取失败：退出码 1；不会加载 BPF module。
```

- `--startup-timeout` 默认 `30s`；`0` 关闭启动期限，负值报错。
- `--shutdown-timeout` 默认 `10s`；`0` 使用该默认值，负值报错。
- 启动失败或事件消费者 panic 会取消其他审计任务；启动/父上下文期限及退出超时返回错误，CLI 退出码为 1。
- 显式取消上下文或 SIGINT，在没有其他错误且清理完成时成功退出；SIGTERM 没有自定义处理器。
- 全部模块禁用时，配置校验成功后即退出，不执行 root、LSM、日志初始化，也不发送就绪通知。
- 就绪表示启用模块已完成同步加载、写 map、附加 hook 和初始化事件缓冲区；不代表异步 DNS 绑定或解析已成功。
- 退出先停止生产者，等待已在处理的事件完成，再释放 module；不保证 libbpf 内部尚未交付的记录全部送达。
- 取消在启动操作之间协作生效，无法强制打断已执行的 Go 回调或 C/内核调用；退出预算限制协调器等待时间。
- DNS 后台任务仍沿用独立生命周期；上述保证覆盖协调器管理的审计任务及其事件消费者。

嵌入调用可使用 `audit.NewApp(version, audit.WithReadyNotification(func(context.Context) error))`。通知错误或 panic 会取消审计任务，通知阻塞也受退出预算约束。通过 `errors.As` 提取 `helpers.StageError` 可识别模块和阶段，通过 `errors.Is` 保留底层错误判断。

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
