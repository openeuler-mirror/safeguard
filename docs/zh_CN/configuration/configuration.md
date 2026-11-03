# 配置说明

## 校验边界与规范化输出

```sh
safeguard controller validate --config safeguard.yaml --normalized > normalized.yaml
diff -u safeguard.yaml normalized.yaml
```

命令输出有效配置的 YAML，不修改输入文件、不加载 BPF；输出文件必须使用其他路径。diff 退出码1表示存在差异。启用的网络规则会掩码CIDR主机位、排序去重身份列表，并将域名转为小写绝对名称后去重。

| 规则 | 接受范围 |
| --- | --- |
| 进程/网络command | 1–15字节且无NUL；进程map最多1024个唯一名称 |
| 文件路径/挂载编码列表 | 最多79字节，与内核比较范围一致；挂载每个源最多63字节 |
| 文件/挂载/UID/GID map | 每表256个唯一项；CIDR按方向、IP族分别最多256项 |
| DNS域名 | 解码后每标签63字节，含根终止符的wire格式最多255字节 |
| DNS代理 | 网络模块启用，bind/upstream非空；上游使用不带端口的IP/主机名，固定53端口 |
| 日志轮转 | 非负；max_size最多8796093022207 MB，max_age最多106751天（int64运算上限） |

旧版以竖线开头的文件deny编码仍可使用，但每段必须为绝对路径且完整编码不能超长。禁用的规则段不做规范化，未知YAML字段仍会被拒绝。

safeguard 的配置文件是 YAML 格式，包含顶层配置节。每个限制模块是一个 YAML 映射，具有各自的 `enable`、`mode`、`target` 和规则字段。

## 当前配置项

| 配置 | 类型 | 说明 |
|:------:|:----|:-----------:|
| `network` | 映射 | 网络访问限制配置，详见[网络限制](../configuration/network-restriction/configuration.md) |
| `files` | 映射 | 文件访问限制配置，详见[文件访问限制](../configuration/file-access-restriction/configuration.md) |
| `mount` | 映射 | 挂载限制配置，详见[挂载限制](../configuration/mount-restriction/configuration.md) |
| `process` | 映射 | 进程限制配置，详见[进程限制](../configuration/process-restriction/configuration.md) |
| `dns_proxy` | 映射 | DNS 代理配置，详见[DNS 代理](../configuration/dns_proxy.md) |
| `policy` | 枚举：`blacklist`、`whitelist` | 策略模式。`blacklist`（默认允许，阻止拒绝项）或 `whitelist`（默认阻止，允许白名单项） |

## 通用限制模块字段

每个限制模块共享以下字段：

| 字段 | 类型 | 说明 |
|:------:|:----|:-----------:|
| `enable` | 布尔值 | 是否启用该限制模块，默认 `false` |
| `mode` | 枚举：`monitor`、`block` | `monitor` 仅记录日志，`block` 阻止匹配事件 |
| `target` | 枚举：`host`、`container` | `host` 全局生效，`container` 仅对容器生效 |

## 配置示例

```yaml
policy: blacklist

network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny: []

files:
  enable: true
  mode: monitor
  target: host

mount:
  enable: true
  mode: block
  target: host
  deny:
    - /var/run/docker.sock

process:
  enable: true
  mode: block
  target: host
  allow:
    - bash
    - ls
```

## 配置验证

启动审计前可以离线校验配置，无需 root 权限，也不会采集主机数据或加载 BPF：

```sh
safeguard controller validate --config config/whitelist.yaml
```

- 文件必须只有一个非 null 的 YAML 文档；未知字段和重复键会被拒绝，即使所属模块未启用。合法的 YAML 锚点和合并键仍可使用。
- 顶层名称使用 `files` 和 `dns_proxy`；进程规则仅支持 `process.allow`，不支持 `process.deny`。
- `policy` 必须为 `blacklist` 或 `whitelist`；启用模块的 `mode` 必须为 `monitor` 或 `block`，`target` 必须为 `host` 或 `container`。
- 启用网络限制时，CIDR allow/deny 项必须能正确解析，域名项不能是空字符串或纯空白，UID/GID allow/deny 项范围为 `0`–`4294967295`。
- `log.max_size` 和 `log.max_age` 不能为负，配置默认值均为 `0`；轮转库将零容量解释为 100 MB，零天数表示不按年龄清理备份。

成功时命令返回零退出码，失败时返回非零并提示配置路径和失败阶段。升级时应修正旧版本静默忽略的拼写错误或过时字段，不要为了消除错误而直接删除规则。
此命令检查语法和配置取值，不验证 DNS 可达性、内核支持或策略是否覆盖业务需求。

## 参见

- [网络限制配置](../configuration/network-restriction/configuration.md)
- [文件访问限制配置](../configuration/file-access-restriction/configuration.md)
- [挂载限制配置](../configuration/mount-restriction/configuration.md)
- [进程限制配置](../configuration/process-restriction/configuration.md)
- [DNS 代理配置](../configuration/dns_proxy.md)
