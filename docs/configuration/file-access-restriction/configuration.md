# Current configuration options

Linux Kernel >= 5.13 is required to use this option.

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable file access restrictions. Default is `false`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, file access events are only logged. If `block` is specified, matching file access is blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction host-wide. Selecting `container` applies the restriction only to containers. |
| `policy` | Enum with the following possible values: `blacklist`, `whitelist` | If `blacklist` is specified (default), allow all except denied. If `whitelist` is specified, deny all except allowed. |
| `allow` | A list of allow file paths | |
| `deny` | A list of allow file paths | |

Set `enable: true` before applying the policy. If `enable` is omitted, safeguard keeps the file access restriction module disabled even when `mode`, `policy`, `allow`, or `deny` are configured.
Use `monitor` mode first when validating a new file access policy, then switch to `block` after the required paths are confirmed.

## Policy Modes

### Blacklist Mode (Default)

In blacklist mode, all file access is allowed by default. Only files in the `deny` list will be blocked.

```yaml
file:
  enable: true
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
  enable: true
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

## Troubleshooting

### File access still blocked after adding to allow list

If you've added a path to the `allow` list but access is still blocked:

1. **Check policy mode**: Ensure `policy: whitelist` is set if you want to use the allow list.
2. **Check path format**: Paths should be absolute (starting with `/`).
3. **Check mode**: If `mode: monitor`, access is only logged, not blocked.

### Whitelist mode blocking too much

In whitelist mode, all access is denied by default. Make sure to:

1. Include all necessary directories (e.g., `/usr`, `/lib`, `/etc`).
2. Test with `mode: monitor` first to identify required paths.
3. Remember that subdirectories are automatically included.

### BPF map errors

If you see errors related to BPF maps:

1. Ensure kernel version is >= 5.13.
2. Check that the BPF filesystem is mounted at `/sys/fs/bpf`.
3. Verify sufficient memory for BPF maps.
