# 配置说明

safeguard 的配置文件是 YAML 格式，包含顶层配置节。每个限制模块是一个 YAML 映射，具有各自的 `enable`、`mode`、`target` 和规则字段。

## 当前配置项

| 配置 | 类型 | 说明 |
|:------:|:----|:-----------:|
| `network` | 映射 | 网络访问限制配置，详见[网络限制](../configuration/network-restriction/configuration.md) |
| `fileaccess` | 映射 | 文件访问限制配置，详见[文件访问限制](../configuration/file-access-restriction/configuration.md) |
| `mount` | 映射 | 挂载限制配置，详见[挂载限制](../configuration/mount-restriction/configuration.md) |
| `process` | 映射 | 进程限制配置，详见[进程限制](../configuration/process-restriction/configuration.md) |
| `dnsproxy` | 映射 | DNS 代理配置，详见[DNS 代理](../configuration/dns_proxy.md) |
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

fileaccess:
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

safeguard 启动时会验证配置文件。如果配置无效，程序会输出错误信息并退出。常见验证规则：

- CIDR 格式必须合法（如 `10.0.0.0/8`）
- 域名格式必须合法（如 `example.com`）
- UID/GID 必须是非负整数
- `mode` 和 `target` 值必须是有效枚举

## 参见

- [网络限制配置](../configuration/network-restriction/configuration.md)
- [文件访问限制配置](../configuration/file-access-restriction/configuration.md)
- [挂载限制配置](../configuration/mount-restriction/configuration.md)
- [进程限制配置](../configuration/process-restriction/configuration.md)
- [DNS 代理配置](../configuration/dns_proxy.md)
