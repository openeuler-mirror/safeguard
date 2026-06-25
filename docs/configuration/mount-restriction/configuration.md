# Current configuration options

Linux Kernel >= 5.13 is required to use this option.

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable mount restrictions. Default is `false`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, mount events are only logged. If `block` is specified, matching mount attempts are blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction host-wide. Selecting `container` applies the restriction only to containers. |
| `deny` | A list of allow file paths | |

Set `enable: true` before applying the policy. If `enable` is omitted, safeguard keeps the mount restriction module disabled even when `mode`, `target`, or `deny` are configured.
Use `monitor` mode first when validating a new mount policy, then switch to `block` after the denied source paths are confirmed.

```yaml
mount:
  enable: true
  mode: block
  target: host
```

!!! warning

    Currently file access restrictions cannot be based on process context (command name, UID, etc).  
    This is because the eBPF Program size becomes too large, and it is failed pass by the eBPF Verifier's limitations.  
    If you can create a better eBPF program, please contribute!
