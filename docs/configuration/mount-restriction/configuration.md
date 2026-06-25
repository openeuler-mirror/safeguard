# Current configuration options

Linux Kernel >= 5.13 is required to use this option.

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable mount restrictions. Default is `false`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, mount events are only logged. If `block` is specified, matching mount attempts are blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction host-wide. Selecting `container` applies the restriction only to containers. |
| `deny` | A list of denied mount source paths | Compared with the mount source path or device name, for example `/var/run/docker.sock`. |

Set `enable: true` before applying the policy. If `enable` is omitted, safeguard keeps the mount restriction module disabled even when `mode`, `target`, or `deny` are configured.
Use `monitor` mode first when validating a new mount policy, then switch to `block` after the denied source paths or device names are confirmed.

```yaml
mount:
  enable: true
  mode: block
  target: host
  deny:
    - /var/run/docker.sock
```

!!! note

    Mount restrictions match the source string passed to the mount operation. For bind mounts, confirm the observed source in monitor mode before adding it to `deny`.

## LSM Hooks

Mount restriction uses the following LSM hooks:

- `sb_mount`: Triggered when a filesystem mount is requested.
- `move_mount`: Triggered when an existing mount is moved.
