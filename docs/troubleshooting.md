# Troubleshooting Guide

## Common Issues

### Controller Generate Fails

**Symptom**: `controller generate` command fails

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
   SAFEGUARD_LOG=DEBUG culinux controller generate
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
   uname -r  # Should be >= 5.10
   ```

### Permission Denied

**Symptom**: `Must be run as root user`

**Solution**: Run with sudo
```bash
sudo culinux controller generate
```

## Debug Mode

Enable debug logging:

```bash
export SAFEGUARD_LOG=DEBUG
culinux --config whitelist.yaml
```

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
culinux controller generate --output test.yaml
# Check test.yaml for correctness
```
