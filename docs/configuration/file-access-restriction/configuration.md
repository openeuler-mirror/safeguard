# Current configuration options

Linux Kernel >= 5.13 is required to use this option.

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable restrictions or not. Default is `true`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, events are only logged. If `block` is specified, network access is blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction to the host-wide. Selecting `container` will apply the restriction only to containers. |
| `policy` | Enum with the following possible values: `blacklist`, `whitelist` | If `blacklist` is specified (default), allow all except denied. If `whitelist` is specified, deny all except allowed. |
| `allow` | A list of allow file paths | |
| `deny` | A list of allow file paths | |

## Policy Modes

### Blacklist Mode (Default)

In blacklist mode, all file access is allowed by default. Only files in the `deny` list will be blocked.

```yaml
file:
  mode: block
  target: host
  policy: blacklist  # or omit for default
  deny:
    - /etc/passwd
    - /etc/shadow
```

### Whitelist Mode

In whitelist mode, all file access is denied by default. Only files in the `allow` list will be permitted.

```yaml
file:
  mode: block
  target: host
  policy: whitelist
  allow:
    - /usr/bin
    - /etc
    - /var/log
```

!!! warning

    Currently file access restrictions cannot be based on process context (command name, UID, etc).  
    This is because the eBPF Program size becomes too large, and it is failed pass by the eBPF Verifier's limitations.  
    If you can create a better eBPF program, please contribute!