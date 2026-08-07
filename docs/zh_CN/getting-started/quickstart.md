# 快速开始

## 编写本地配置

创建一个配置文件 `safeguard.yml`：

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

此配置将以 monitor 模式监控网络访问，阻止对云元数据服务（169.254.169.254）的访问。

## 启动 safeguard

```bash
sudo ./build/safeguard --config safeguard.yml
```

## 验证运行

safeguard 启动后会输出日志，确认各模块已加载：

```
safeguard: network module enabled (mode=monitor, target=host)
safeguard: BPF programs loaded successfully
```

## 切换到 block 模式

确认 monitor 模式下日志正常后，将配置切换为 block 模式：

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

重启 safeguard：

```bash
sudo ./build/safeguard --config safeguard.yml
```

## 使用白名单模式

通过 controller 模块自动生成白名单配置：

```bash
sudo ./build/safeguard controller generate --output whitelist.yaml
```

应用白名单配置：

```bash
sudo ./build/safeguard --config whitelist.yaml
```

## 添加更多限制模块

在配置文件中添加文件访问、挂载和进程限制：

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32

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
    - cat
```

## 下一步

- [安装指南](./installation.md)：详细的安装和依赖说明
- [配置说明](../configuration/configuration.md)：完整的配置项参考
- [故障排除](../troubleshooting.md)：常见问题解决
