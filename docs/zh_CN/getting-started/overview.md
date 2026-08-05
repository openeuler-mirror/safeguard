# 概述

safeguard 检测并控制四类安全事件：

- [网络访问](../configuration/network-restriction/configuration.md)：基于 CIDR 和域名控制网络连接
- [文件访问](../configuration/file-access-restriction/configuration.md)：基于路径控制文件读写操作
- [挂载操作](../configuration/mount-restriction/configuration.md)：基于源路径控制挂载行为
- [进程执行](../configuration/process-restriction/configuration.md)：基于命令路径控制进程执行

## 工作模式

每种限制支持两种模式：

| 模式 | 行为 |
|------|------|
| monitor | 仅记录安全事件日志，不阻止 |
| block | 阻止匹配的安全事件并记录日志 |

## 作用范围

每种限制支持两种作用范围：

| 范围 | 说明 |
|------|------|
| host | 在整个主机范围内生效 |
| container | 仅对容器环境生效 |

## 策略模式

safeguard 支持两种策略模式：

| 策略 | 说明 |
|------|------|
| blacklist | 默认允许，仅阻止拒绝列表中的项 |
| whitelist | 默认阻止，仅允许白名单中的项 |

## 技术架构

safeguard 基于 eBPF 和 Linux Security Module (LSM) 实现安全控制。eBPF 程序挂载到 LSM 钩子点，在内核层面拦截安全事件，用户态程序负责配置管理和日志输出。

```
用户态                    内核态
┌──────────┐    BPF Map    ┌──────────────┐
│ safeguard │ ────────────▶ │  eBPF 程序    │
│  配置管理  │ ◀──────────── │  LSM 钩子     │
│  日志输出  │   事件上报    │  网络拦截     │
└──────────┘              └──────────────┘
```

## 前置要求

- Linux Kernel >= 5.13
- 内核开启 BPF LSM 支持（`CONFIG_BPF_LSM=y`）
- BTF 支持（`CONFIG_DEBUG_INFO_BTF=y`）
- root 权限
