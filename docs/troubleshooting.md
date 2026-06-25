# Troubleshooting Guide

## Common Issues

### Controller Generate Fails

**Symptom**: `safeguard controller generate` command fails

**Solutions**:
1. Check file permissions
   ```bash
   ls -la /etc/passwd /proc
   ```
2. Verify network interfaces
   ```bash
   ip addr show
   ```
3. Run with debug logging
   ```bash
   SAFEGUARD_LOG=DEBUG safeguard controller generate
   ```

### BPF Map Errors

**Symptom**: `failed to update BPF map`

**Solutions**:
1. Check BPF filesystem
   ```bash
   mount | grep bpf
   ```
2. Verify kernel version
   ```bash
   uname -r  # Should be >= 5.13
   ```
3. Check required BPF and BTF kernel options
   ```bash
   zgrep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /proc/config.gz || \
     grep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /boot/config-$(uname -r)
   ```
   Both options should be set to `y`.
4. Confirm that BPF LSM is active
   ```bash
   cat /sys/kernel/security/lsm
   ```
   The output must include `bpf`. If it does not, add `bpf` to the `lsm=` boot parameter and reboot.

### Permission Denied

**Symptom**: `Must be run as root user`

**Solution**: Run with sudo
```bash
sudo safeguard controller generate
```

## Debug Mode

Enable debug logging:

```bash
export SAFEGUARD_LOG=DEBUG
safeguard --config whitelist.yaml
```

Use `whitelist.yaml` for controller-generated whitelist configs. For the repository default sample, use `config/safeguard.yml`.

## Log Analysis

Check logs for errors:

```bash
# JSON format
journalctl -u safeguard -o json | jq 'select(.level=="error")'

# Text format
grep "error" /var/log/safeguard.log
```

## Validation

Validate configuration:

```bash
safeguard controller generate --output test.yaml
# Check test.yaml for correctness
```
