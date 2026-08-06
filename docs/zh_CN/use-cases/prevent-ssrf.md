# 防止 SSRF 攻击

服务端请求伪造（SSRF）是一种攻击者可以诱使服务器向非预期目标发起请求的漏洞。在云环境中，元数据服务（169.254.169.254）是常见的 SSRF 攻击目标，可能暴露实例凭证。

## 阻断云元数据服务

阻断对公有云元数据服务的访问。这是针对以云实例元数据为目标的 SSRF 攻击的缓解措施。

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

## 阻断内网访问

对于仅需访问公网的工作负载，阻断内网地址范围：

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 169.254.169.254/32
```

## 仅容器 SSRF 防护

仅对容器应用 SSRF 防护：

```yaml
network:
  enable: true
  mode: block
  target: container
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

## 先监控后阻断

使用监控模式验证策略效果后再切换为阻断模式：

```yaml
network:
  enable: true
  mode: monitor
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

查看日志确认策略按预期工作后，切换为 `block` 模式。

## 结合域名过滤

通过 DNS 代理按域名阻断 SSRF：

```yaml
network:
  enable: true
  mode: block
  target: host
  domain:
    deny:
      - metadata.google.internal
      - metadata.azure.com

dnsproxy:
  enable: true
  listen: "127.0.0.1:53"
  upstream:
    - 8.8.8.8
```
