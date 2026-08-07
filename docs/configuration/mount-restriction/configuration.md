# Mount Restriction Configuration

Linux Kernel >= 5.13 is required to use this option.

## Configuration Options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable mount restrictions. Default is `false`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, mount events are only logged. If `block` is specified, matching mount attempts are blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction host-wide. Selecting `container` applies the restriction only to containers. |
| `deny` | A list of denied mount source paths | Compared with the mount source path or device name, for example `/var/run/docker.sock`. |

Set `enable: true` before applying the policy. If `enable` is omitted, safeguard keeps the mount restriction module disabled even when `mode`, `target`, or `deny` are configured.
Use `monitor` mode first when validating a new mount policy, then switch to `block` after the denied source paths or device names are confirmed.

## Basic Configuration

Block the Docker socket from being mounted into containers:

```yaml
mount:
  enable: true
  mode: block
  target: host
  deny:
    - /var/run/docker.sock
```

## Monitor Mode

Use monitor mode to log mount events without blocking them. This is useful for validating a policy before enforcement:

```yaml
mount:
  enable: true
  mode: monitor
  target: host
  deny:
    - /var/run/docker.sock
    - /dev/sda1
```

Review the logs to confirm the denied paths are correct, then switch to `block` mode.

## Container-Targeted Restriction

Apply mount restrictions only to containers, leaving host processes unrestricted:

```yaml
mount:
  enable: true
  mode: block
  target: container
  deny:
    - /var/run/docker.sock
    - /proc/sysrq-trigger
```

## Multiple Deny Paths

Deny multiple mount source paths in a single policy:

```yaml
mount:
  enable: true
  mode: block
  target: host
  deny:
    - /var/run/docker.sock
    - /dev/sda1
    - /sys/kernel/security
```

!!! note

    Mount restrictions match the source string passed to the mount operation. For bind mounts, confirm the observed source in monitor mode before adding it to `deny`.

## LSM Hooks

Mount restriction uses the following LSM hooks:

- `sb_mount`: Triggered when a filesystem mount is requested.
- `move_mount`: Triggered when an existing mount is moved.

## Troubleshooting

### Mount restriction not working

1. Verify `enable: true` is set in the configuration.
2. Check that BPF LSM is enabled: `cat /sys/kernel/security/lsm | grep bpf`
3. Ensure the kernel version is >= 5.13.
4. Check safeguard logs for mount events in monitor mode.

### False positives in monitor mode

If legitimate mount operations are being flagged, refine the `deny` list to be more specific. Use exact source paths rather than broad patterns.
