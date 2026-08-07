# 白名单策略设计文档

## 架构概览

白名单策略系统由三层组成：

```
┌─────────────────────────────────────────────────┐
│                  CLI 层                          │
│  safeguard controller generate                  │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│               服务层                             │
│  编排采集和生成流程                              │
└─────────────────────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ 采集层   │  │  模型层   │  │  渲染层  │
    │          │  │          │  │          │
    └──────────┘  └──────────┘  └──────────┘
```

## 采集器接口

```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

### 实现列表

| 采集器 | 数据源 | 输出 |
|-----------|--------|------|
| PasswdCollector | /etc/passwd | 用户账号 |
| ProcCollector | /proc/* | 运行进程 |
| NetworkCollector | /sys/class/net | 网络接口 |

## 模型转换

`BuildWhitelist` 函数将原始数据转换为白名单模型：

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel
```

### 去重

- `uniqueStrings()` 去除重复字符串
- `uniqueUints()` 去除重复整数

## 策略执行流程

```
配置 → BPF 映射 → LSM 钩子 → 内核执行
```

## 默认输出

`safeguard controller generate` 默认输出 `demo-whitelist.yaml` 和 `demo-whitelist-report.json`。可以通过 `--output` 和 `--report` 覆盖。

### 策略模式

| 模式 | 行为 |
|------|------|
| blacklist | 默认允许，阻止拒绝项 |
| whitelist | 默认阻止，允许白名单项 |
