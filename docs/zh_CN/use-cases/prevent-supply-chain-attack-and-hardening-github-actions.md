# 防止供应链攻击与加固 GitHub Actions 自托管 Runner

近年来，由于供应链攻击导致 CI/CD 环境中凭证泄露的事件屡见不鲜。
签名验证和哈希验证有助于防止供应链攻击，而出站限制是另一项应采取的措施。
safeguard 可以安装在 CI/CD 环境中，通过域名或进程名限制网络通信。

## 加固 GitHub Actions 自托管 Runner

在 GitHub Actions 自托管 Runner 上加固工作流，按以下步骤操作：

### 1. 安装 safeguard

参考 [安装指南](../getting-started/installation.md) 安装 safeguard。

### 2. 创建 safeguard 配置文件

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    # 添加 Runner 使用的 DNS 服务器和内网地址
    allow: ["8.8.8.8/32", "8.8.4.4/32", "127.0.0.1/32", "10.0.0.8/32", "172.16.0.0/12", "192.168.0.0/16"]
  domain:
    allow:
      # https://docs.github.com/ja/actions/hosting-your-own-runners/about-self-hosted-runners#
      - "github.com"
      - "api.github.com"
      - "codeload.github.com"
      - "objects.github.com"
      - "objects.githubusercontent.com"
      - "objects-origin.githubusercontent.com"
      - "github-releases.githubusercontent.com"
      - "github-registry-files.githubusercontent.com"
dns_proxy:
  enable: true
  # 代理查询的上游 DNS 服务器
  upstreams:
    - 8.8.8.8
    - 8.8.4.4
  # 监听本地地址和 Docker 默认网桥地址
  bind:
    - 127.0.0.1
    - 172.17.0.1
log:
  format: json
```

### 3. 更改 DNS 服务器

将 `/etc/resolv.conf` 指向 `dns_proxy.bind` 中配置的地址。
代理将请求转发到 `dns_proxy.upstreams`。包含 `172.17.0.1`（Docker 默认网桥地址），使容器可以通过代理解析域名。

```shell
$ cat /etc/resolv.conf
nameserver 127.0.0.1
nameserver 172.17.0.1
search .
```

如果使用 systemd-resolved，请勿修改 `/etc/resolv.conf`。在 `/etc/systemd/resolved.conf` 中设置 `DNS` 为相同的 `dns_proxy.bind` 地址。

```shell
# cat /etc/systemd/resolved.conf
[Resolve]
DNS=127.0.0.1 172.17.0.1

# systemctl restart systemd-resolved
```
