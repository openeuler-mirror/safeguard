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
    ├─ MarshalReportJSON()  → JSON bytes (可选)
    ├─ WriteFile()          → 保存 YAML 配置
    └─ WriteFile()          → 保存 JSON 报告 (可选)
```

CLI 默认输出 `demo-whitelist.yaml` 和 `demo-whitelist-report.json`，可以通过 `--output` 和 `--report` 覆盖。默认生成的配置可通过 `safeguard --config demo-whitelist.yaml` 应用。

当采集或规则转换产生警告时，必须提供报告路径，以免遗漏规则未被察觉。

YAML 和可选报告先完成编码；有警告时先写报告，报告失败不会改写配置。
没有警告时先写 YAML，再写可选报告；后者失败时已写入的 YAML 不会回滚。`processcheck` 是独立匹配工具，不参与上述生成流程，也不代表内核策略的执行结果。

## 审阅生成警告

先用监控模式生成配置和报告：

```sh
safeguard controller generate --mode monitor --output whitelist.yaml --report report.json
safeguard controller validate --config whitelist.yaml
python3 -c 'import json; print("\n".join(json.load(open("report.json"))["warnings"]))'
```

报告的 `warnings` 可能指出无法读取的网络表、超过长度限制的路径、
含斜杠的进程名、根目录账号 home，或超出 BPF 映射容量的条目。
被跳过或截断的条目不会自动替换为更宽泛的规则；请根据实际业务需求
核对报告和生成的 `files.allow`、`process.allow` 及网络列表。
校验只检查配置格式和静态约束，不证明策略覆盖完整或内核实际拦截成功。
确认监控结果和规则范围后，再决定是否使用阻断模式。
