# 白名单策略用户手册

## 概述

白名单策略功能支持基于当前主机状态自动生成配置。生成默认使用 monitor 模式，
不会阻断违规操作；启用阻断前应先审查生成结果。

## 配置

### 策略模式

| 模式 | 说明 |
|------|------|
| blacklist | 允许所有，仅拒绝列出的项目（默认） |
| whitelist | 拒绝所有，仅允许列出的项目 |

```yaml
policy: whitelist
```

### 生成白名单

以下示例使用已安装的 `safeguard` 命令。

```bash
safeguard controller generate
```

默认情况下，该命令会写入 `demo-whitelist.yaml` 和 `demo-whitelist-report.json`。
需要自定义文件名时，使用 `--output` 和 `--report` 参数：

```bash
safeguard controller generate --output whitelist.yaml --report report.json
```

## 生成的组件

### 网络
- 网络接口的本机地址及 `/proc/net` 中的远端地址
- 来自账号和运行进程的 UID/GID
- 空的命令允许列表

### 进程
- 从运行中的可执行文件或进程命令提取的名称

### 文件访问
- 主目录
- 可执行文件路径

### 报告
- JSON 摘要，默认写入 `demo-whitelist-report.json`

## 应用配置

```bash
safeguard --config demo-whitelist.yaml
```

如果生成时使用了 `--output whitelist.yaml`，则应用该文件。

## 模式对比

| 方面 | 监控模式 | 阻断模式 |
|------|----------|----------|
| 效果 | 观察策略违规 | 执行策略 |
| 动作 | 仅记录 | 阻止访问 |
| 典型用途 | 执行前审查 | 审查后执行 |
