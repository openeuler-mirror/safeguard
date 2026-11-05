# DNS 代理

## 解析期限与刷新生命周期

审计解析器对多上游和UDP到TCP重试使用一次总期限。默认采用resolv.conf的正超时（最多30秒），未设置时为5秒；显式DNS client超时优先，调用方更短的deadline仍优先。

- SERVFAIL和REFUSED可以尝试下一上游；NXDOMAIN立即返回，NODATA与传输失败分别识别。
- 响应必须匹配问题和操作码；地址只接受请求名称或同一响应内最多16跳CNAME链的结果，循环单独报错。
- 有效TTL取相关地址和别名的最小值；答案保留真实的零TTL，代理反查缓存不保留零TTL结果。
- 刷新失败会暴露错误，名义退避依次为5、10、20、40、60秒，成功后重置。每个任务的抖动取延迟的80–100%，且至少1秒；成功刷新不会因抖动推迟到正TTL之后。
- 网络审计取消会传到支持context的解析器，并中断刷新等待；Stop/Close等待已启动的刷新任务结束后再释放资源。旧Resolver须自行返回，无法强制打断其调用。
- 审计已知取消后，后续DNS地址更新会在访问BPF前返回取消错误。反查缓存TTL影响日志归属，不会单独撤销已有BPF地址项。

异步审计解析器与监听DNS代理的生命周期分别管理。有界worker池、查询合并和有界陈旧结果策略仍待设计，目前没有对应配置选项。

如果需要通过[指定域名](./network-restriction/configuration.md)控制访问，需要选择"周期性名称解析"或"更换 DNS 服务器"。
默认使用"周期性名称解析"，推荐使用"更换 DNS 服务器"。

## 周期性名称解析

safeguard 按固定间隔解析域名，将解析结果（IP 地址）写入 BPF 映射。
这种方式不需要修改系统 DNS 配置，但存在解析延迟——域名解析结果更新前，新 IP 可能无法立即生效。

配置示例：

```yaml
network:
  enable: true
  mode: block
  target: host
  domain:
    allow:
      - example.com
dns_proxy:
  enable: false
```

## 更换 DNS 服务器

safeguard 启动本地 DNS 代理并转发查询；匹配域名规则的地址用于更新网络策略。
这种方式根据代理查询结果更新地址规则，需要将系统 DNS 指向 safeguard 代理。

配置示例：

```yaml
network:
  enable: true
  mode: block
  target: host
  domain:
    allow:
      - example.com
dns_proxy:
  enable: true
  bind:
    - 127.0.0.1
  upstreams:
    - 8.8.8.8
    - 1.1.1.1
```

## DNS 代理配置项

| 配置 | 类型 | 说明 |
|:------:|:----|:-----------:|
| `enable` | 布尔值 | 是否启用 DNS 代理，默认 `false` |
| `bind` | 字符串列表 | DNS 代理监听地址；端口固定为 53 |
| `upstreams` | 字符串列表 | 上游 DNS 服务器列表；端口固定为 53 |

## 代理行为与排错

- 代理只接受单个 IN 类问题；首次交换传输错误、SERVFAIL 或 REFUSED 时尝试下一上游，NXDOMAIN 直接返回。UDP 响应截断时对该上游重试一次 TCP。
- 代理每次上游交换使用 client 超时，不与审计解析器共享总期限；响应写出失败会记录日志。
- 仅问题对应的 A/AAAA 记录和同一响应内的 CNAME 链参与缓存与策略更新。反查缓存按 TTL 过期，最多保存 4096 个 IP，每个 IP 最多 16 个域名。
- 配置加载会拒绝重复监听、IPv4 通配监听与具体 IPv4 监听冲突，以及可静态确认的上游自指；检查时不会解析主机名。
- 可使用 `safeguard controller validate --config <路径>` 离线检查配置，并在代理日志中查找上游和响应写出错误。

## 注意事项

- 启用 DNS 代理后，需要将系统 DNS 配置指向代理地址
- DNS 代理需要 root 权限监听 53 端口
- 如果上游 DNS 不可达，域名解析会失败
