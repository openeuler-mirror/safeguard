# DNS 代理

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
dnsproxy:
  enable: false
```

## 更换 DNS 服务器

safeguard 启动本地 DNS 代理服务器，拦截 DNS 请求并根据域名规则进行过滤。
这种方式实时性更强，域名规则变更立即生效，但需要将系统 DNS 指向 safeguard 代理。

配置示例：

```yaml
network:
  enable: true
  mode: block
  target: host
  domain:
    allow:
      - example.com
dnsproxy:
  enable: true
  listen: "127.0.0.1:53"
  upstream:
    - 8.8.8.8
    - 1.1.1.1
```

## DNS 代理配置项

| 配置 | 类型 | 说明 |
|:------:|:----|:-----------:|
| `enable` | 布尔值 | 是否启用 DNS 代理，默认 `false` |
| `listen` | 字符串 | DNS 代理监听地址，格式 `host:port` |
| `upstream` | 字符串列表 | 上游 DNS 服务器列表 |

## 注意事项

- 启用 DNS 代理后，需要将系统 DNS 配置指向代理地址
- DNS 代理需要 root 权限监听 53 端口
- 如果上游 DNS 不可达，域名解析会失败
