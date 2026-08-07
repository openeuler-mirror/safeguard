# Controller 架构

## 组件

### 服务层

`Service` 是 controller 的顶层编排器，串联数据采集、模型构建和渲染输出：

```go
service := Service{
    Collector: &SnapshotCollector{},
    Now:       time.Now,
}
result, err := service.Generate()
```

### 采集层

`SnapshotCollector` 接口定义了主机数据采集的契约：

```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

内置采集器：

| 采集器 | 数据源 | 输出 |
|--------|--------|------|
| PasswdCollector | /etc/passwd | 用户账号信息 |
| ProcCollector | /proc/* | 运行进程信息 |
| NetworkCollector | /sys/class/net | 网络接口和 CIDR |

### 模型层

`BuildWhitelist` 函数将原始采集数据转换为白名单模型：

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel
```

转换过程包括：
- CIDR 去重和格式化
- UID/GID 去重
- 进程命令去重
- 文件路径去重

### 渲染层

渲染层将白名单模型输出为 safeguard 可用的 YAML 配置和 JSON 报告：

- `MarshalConfigYAML()`：生成 YAML 配置
- `MarshalReportJSON()`：生成 JSON 报告

## 数据流

```
CLI 入口 (safeguard controller generate)
    │
    ▼
command.go ──解析 --mode/--output/--report──▶ Service.Generate()
    │
    ▼
service.go
    ├─ Collector.Collect()  → HostSnapshot
    ├─ BuildWhitelist()     → WhitelistModel
    ├─ MarshalConfigYAML()  → YAML bytes
    ├─ WriteFile()          → 保存 YAML 配置
    ├─ MarshalReportJSON()  → JSON bytes (可选)
    └─ WriteFile()          → 保存 JSON 报告 (可选)
```

## 默认输出

`controller generate` 默认输出 `demo-whitelist.yaml` 和 `demo-whitelist-report.json`。
可以通过 `--output` 和 `--report` 覆盖输出路径。
