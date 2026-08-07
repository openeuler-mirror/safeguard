# 故障排除指南

## 常见问题

### safeguard 启动失败：BPF LSM 未启用

**症状**：启动时报错 `BPF LSM is not enabled`

**原因**：内核未启用 BPF LSM 支持

**解决方法**：

1. 检查内核配置：
   ```bash
   grep CONFIG_BPF_LSM /boot/config-$(uname -r)
   ```
   应输出 `CONFIG_BPF_LSM=y`

2. 检查 LSM 启用顺序：
   ```bash
   cat /sys/kernel/security/lsm
   ```
   输出中应包含 `bpf`

3. 如果未包含，修改 grub 引导参数：
   ```bash
   GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
   sudo update-grub
   sudo reboot
   ```

### BPF 程序加载失败

**症状**：`failed to load BPF program`

**原因**：内核版本过低或 BTF 不支持

**解决方法**：

1. 确认内核版本 >= 5.13：`uname -r`
2. 确认 BTF 支持：`ls /sys/kernel/btf/vmlinux`
3. 如果 BTF 文件不存在，需要重新编译内核启用 `CONFIG_DEBUG_INFO_BTF=y`

### 配置文件格式错误

**症状**：`config validation failed`

**解决方法**：

1. 检查 YAML 格式是否正确：
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('safeguard.yml'))"
   ```
2. 确认 CIDR 格式合法（如 `10.0.0.0/8`，不是 `10.0.0.0`）
3. 确认 `mode` 和 `target` 值是有效枚举（`monitor`/`block`，`host`/`container`）

### 权限不足

**症状**：`operation not permitted`

**解决方法**：safeguard 需要 root 权限运行：`sudo ./build/safeguard --config safeguard.yml`

### DNS 代理启动失败

**症状**：`failed to start DNS proxy`

**原因**：53 端口被占用或权限不足

**解决方法**：

1. 检查端口占用：`ss -tlnp | grep :53`
2. 如果被 systemd-resolved 占用，可以修改 DNS 代理监听端口
3. 确保使用 root 权限运行

### 日志输出异常

**症状**：事件日志为空或格式异常

**解决方法**：

1. 确认对应模块已启用（`enable: true`）
2. 确认 `mode` 设置正确（`monitor` 模式会记录所有事件）
3. 检查 `target` 是否匹配当前环境（`host` vs `container`）

## 调试模式

可以通过环境变量启用调试日志：

```bash
SAFEGUARD_DEBUG=1 sudo ./build/safeguard --config safeguard.yml
```

## 获取帮助

- [GitHub Issues](https://atomgit.com/openeuler/safeguard/issues)
- [配置说明](./configuration/configuration.md)
