# safeguard controller - 代码讲解

## 概述

`pkg/controller` 模块用于生成白名单配置，通过采集主机数据（用户、进程、网络）自动生成 safeguard 所需的 YAML 配置文件，并可同时输出 JSON 报告。

## 项目结构

```
pkg/controller/
├── model/                    # 数据模型层
│   ├── types.go              # 结构体定义
│   └── build.go              # 白名单构建逻辑
├── collector/                # 数据采集层
│   ├── passwd.go             # /etc/passwd 解析
│   ├── network.go            # 网络信息采集
│   ├── proc.go               # 进程信息采集
│   └── snapshot.go           # 采集器入口
├── render/                   # 渲染输出层
│   └── render.go             # YAML/JSON 输出
├── processcheck/             # 进程白名单检查
│   └── matcher.go            # 白名单匹配器
├── service.go                # 服务层（串联各层）
└── command.go                # CLI 命令定义
```

## 数据流架构

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
    │
    ▼
collector/ ◀───────────── model/ ◀───────────── render/
```

CLI 默认输出 `demo-whitelist.yaml` 和 `demo-whitelist-report.json`，可以通过 `--output` 和 `--report` 覆盖。
