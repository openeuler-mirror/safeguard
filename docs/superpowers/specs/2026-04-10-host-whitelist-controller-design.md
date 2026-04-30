# 主机白名单管控 Demo 设计

## 背景

本次需求基于专利“主机管控方法、装置、设备和存储介质（CN202211464751.X）”的核心思想，在当前 `safeguard` 项目基础上实现一个可演示的基础版本。

专利的关键点是：

- 管控端根据主机信息生成白名单
- 白名单覆盖网络、账号、文件、进程四类信息
- 主机根据白名单进行监督或阻断
- 白名单后续可通过 SSH 等安全通道下发

本次只实现 demo，不实现 SSH 下发链路，优先完成“白名单生成 + 主机侧生效”的最小闭环。

## 目标

在同一个 `safeguard` 二进制中增加一个“管控端”角色，用于采集本机主机信息并自动生成白名单，再将白名单渲染为现有 `safeguard` 可消费的配置文件，以复用现有网络、文件、挂载审计与限制能力。

demo 的完成状态应满足以下要求：

- 可以通过命令生成白名单 YAML 配置文件
- 可以同时导出一份 JSON 报告，展示四类白名单内容
- 生成出的 YAML 能被现有配置解析流程正常加载
- 启动 `safeguard` 后，网络和文件模块按现有机制进入监控
- 进程白名单以“监督”方式生效，能够识别白名单外进程事件

## 范围

### 本次实现范围

- 新增 `controller` 子命令
- 采集主机网络、账号、文件、进程信息
- 生成统一白名单模型
- 渲染为 `safeguard` YAML 配置和 JSON 报告
- 扩展进程配置结构，支持 `process.allow`
- 在用户态对进程事件做白名单监督

### 明确不做

- 不实现 SSH 下发
- 不实现中心化服务端或多主机管理
- 不实现进程白名单的内核态阻断
- 不改变现有 eBPF 文件、网络、挂载主链路

## 现状与约束

当前仓库已经具备以下能力：

- `network` 模块可根据 CIDR、域名、UID、GID、命令进行监控或阻断
- `files` 模块可根据允许/拒绝路径进行监控或阻断
- `mount` 模块可根据拒绝源路径进行监控或阻断
- `process` 模块当前主要提供进程创建和执行事件审计

当前仓库也存在一个重要限制：

- `process` 模块没有完整的“进程白名单配置下发 + 内核态阻断”能力，因此本次只能将进程白名单实现为用户态监督逻辑

这个限制需要在设计、实现和演示话术中显式说明，避免把“可采集”误表述成“可阻断”。

## 总体架构

### 角色划分

同一个可执行文件承担两个角色：

- 执行端：保留现有 `safeguard --config <path>` 行为
- 管控端：新增 `safeguard controller generate` 行为

### 命令形态

demo 采用两步式命令，职责分离：

```bash
safeguard controller generate --output demo-whitelist.yaml --report demo-whitelist-report.json
safeguard --config demo-whitelist.yaml
```

第一步完成白名单生成，第二步复用现有执行链路进行主机侧监控。

### 架构原则

- 不入侵现有 `audit` 主流程
- 管控端生成逻辑与执行端审计逻辑分离
- 白名单使用统一模型表达，再映射为现有配置结构
- 默认采用 `monitor` 模式，减少 demo 风险

## 模块设计

建议新增以下包：

- `pkg/controller`
  - 负责 `controller generate` 命令入口和主流程编排
- `pkg/controller/collector`
  - 负责采集网络、账号、文件、进程信息
- `pkg/controller/model`
  - 负责定义 `HostSnapshot` 和 `WhitelistModel`
- `pkg/controller/render`
  - 负责输出 YAML 配置和 JSON 报告
- `pkg/controller/processcheck`
  - 负责进程事件白名单监督

现有模块的改动应尽量小：

- `pkg/config`
  - 为 `process` 增加 `allow` 字段
- `pkg/audit/process`
  - 在现有进程事件日志基础上增加白名单判断
- `pkg/audit/app`
  - 为 CLI 新增 `controller` 子命令入口

## 数据模型

### HostSnapshot

`HostSnapshot` 表示采集阶段得到的原始主机信息，包含：

- `hostname`
- `interfaces`
- `cidrs`
- `accounts`
- `uids`
- `gids`
- `running_processes`
- `executable_paths`
- `warnings`

### WhitelistModel

`WhitelistModel` 表示归一化后的白名单语义层，包含：

- `network.cidr_allow`
- `network.uid_allow`
- `network.gid_allow`
- `accounts.users`
- `files.allow`
- `process.allow`
- `metadata.generated_at`
- `metadata.hostname`
- `warnings`

这个模型不直接绑定现有 YAML 结构，目的是把“专利中的白名单语义”与“当前工程实现格式”隔离开，便于后续扩展 SSH 下发或服务端版本。

## 采集规则

### 网络白名单

采集来源：

- 本机网络接口地址
- 当前活跃连接中的目标地址

建议实现方式：

- 通过 `net.Interfaces()` 采集本机接口和 CIDR
- 从 `/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/udp`、`/proc/net/udp6` 提取活跃连接地址

归一化规则：

- 去重
- 排序
- 对单 IP 统一转成 `/32` 或 `/128`

输出映射：

- 写入 `network.cidr.allow`

### 账号白名单

采集来源：

- `/etc/passwd`
- 当前运行进程所属 UID/GID

归一化规则：

- 仅保留可解析用户名的账号记录
- 去重 UID/GID
- 排序输出

输出映射：

- 报告文件中展示完整账号信息
- YAML 中写入 `network.uid.allow`
- YAML 中写入 `network.gid.allow`

### 文件白名单

采集来源：

- 当前运行进程的可执行文件路径
- 白名单账号的 home 目录
- 基础系统路径

基础系统路径固定包含：

- `/`
- `/bin`
- `/usr/bin`
- `/usr/sbin`
- `/lib`
- `/lib64`
- `/etc`

归一化规则：

- 只保留存在的路径
- 去重
- 路径按字典序排序

输出映射：

- 写入 `files.allow`

### 进程白名单

采集来源：

- 当前运行进程的 `comm`
- 当前运行进程的可执行文件名

归一化规则：

- 去重
- 过滤空值
- 排序

输出映射：

- 报告文件中展示完整进程白名单
- YAML 中写入新增字段 `process.allow`

需要特别说明：

- `process.allow` 本次仅供用户态监督逻辑使用
- 不承诺内核态拦截

## 配置映射

controller 生成的 YAML 需要兼容现有 `config.NewConfig()` 流程。

默认输出策略如下：

- `network.mode: monitor`
- `network.target: host`
- `network.cidr.allow: controller 采集并归一化后的 CIDR 列表`
- `network.uid.allow: controller 采集并去重后的 UID 列表`
- `network.gid.allow: controller 采集并去重后的 GID 列表`
- `network.command.allow: []`
- `files.mode: monitor`
- `files.target: host`
- `files.allow: controller 采集并筛选后的路径白名单`
- `files.deny: []`
- `process.mode: monitor`
- `process.target: host`
- `process.allow: controller 采集并去重后的进程名称白名单`
- `mount.mode: monitor`
- `mount.target: host`
- `mount.deny: []`

原因如下：

- `monitor` 模式更适合 demo，避免白名单不完整时直接影响主机可用性
- `mount` 不纳入本次自动生成主线，但保留结构以兼容现有配置模型
- `command.allow` 暂不自动生成，避免误把进程白名单语义映射成网络命令约束

## 进程白名单监督

### 行为定义

进程事件到达用户态后，使用 `process.allow` 对以下字段进行匹配：

- 进程 `comm`
- 父进程 `parent_comm`

匹配成功：

- 继续输出现有进程事件日志

匹配失败：

- 输出一条额外的异常日志，标记为“未命中进程白名单”

### 监督逻辑定位

该逻辑放在用户态，不修改 eBPF 程序，理由如下：

- 当前进程模块没有完整配置 map 和阻断逻辑
- 用户态监督足以完成 demo 的“白名单外行为监督”演示
- 后续若要扩展到阻断，可在现有白名单模型之上继续演进

## 输出文件

### YAML

用途：

- 被现有 `safeguard --config` 直接加载

特性：

- 稳定排序
- 省略无意义的冗余字段
- 结构兼容现有配置解析器

### JSON 报告

用途：

- 用于展示管控端生成了哪些白名单
- 辅助专利 demo 讲解

建议字段：

- `hostname`
- `generated_at`
- `network`
- `accounts`
- `files`
- `processes`
- `warnings`

## 错误处理与回退策略

controller 生成流程应尽量“部分成功”，而不是“全有或全无”。

规则如下：

- 某一类采集失败时，不中断整体流程
- 将失败原因写入 `warnings`
- YAML 和 JSON 仍然输出
- 所有集合类输出统一做去重和排序

安全回退策略如下：

- 文件白名单最少保留 `/`
- 网络白名单最少保留本机已知接口地址
- 进程白名单为空时，只输出采集结果，不判定异常

## 演示流程

建议 demo 按以下顺序展示：

1. 运行 `safeguard controller generate --output demo-whitelist.yaml --report demo-whitelist-report.json`
2. 展示 `demo-whitelist-report.json` 中的网络、账号、文件、进程白名单
3. 展示 `demo-whitelist.yaml` 已经映射为 `safeguard` 配置
4. 运行 `safeguard --config demo-whitelist.yaml`
5. 执行一个白名单外进程或异常访问动作
6. 展示日志中出现的监督信息

## 验收标准

- 可以生成一份合法 YAML 和一份合法 JSON
- YAML 可以被现有配置解析器加载
- 网络和文件模块可以使用该 YAML 正常启动
- 报告文件能完整体现四类白名单
- 白名单外进程事件会输出监督日志

## 后续扩展

本次设计刻意保留后续扩展空间：

- 可在 `WhitelistModel` 基础上增加 SSH 下发器
- 可增加“中心化管控端 + 主机注册”模式
- 可将 `process.allow` 从用户态监督演进为内核态阻断
- 可将生成流程扩展为周期性白名单更新

## 结论

本方案以最小改动复用当前 `safeguard` 的执行能力，把“白名单生成”补到项目中，形成一个可演示的主机白名单管控 demo。

它不追求一次性补全专利的所有工程环节，而是优先实现以下闭环：

- 采集主机信息
- 生成四类白名单
- 输出可执行配置
- 启动现有管控能力
- 对白名单外进程进行监督

这条路径开发成本低、风险可控，且为后续补 SSH 下发和中心化管控保留了清晰的演进方向。
