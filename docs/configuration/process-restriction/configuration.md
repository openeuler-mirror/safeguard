# Current configuration options

Linux Kernel >= 5.13 is required to use this option.

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable process restrictions. Default is `false`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, process execution events are only logged. If `block` is specified, matching process execution is blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction host-wide. Selecting `container` applies the restriction only to containers. |
| `allow` | A list of allowed process names | Used when the global `policy` is `whitelist`. |

Set `enable: true` before applying the policy. If `enable` is omitted, safeguard keeps the process restriction module disabled even when `mode`, `target`, or `allow` are configured.
Use `monitor` mode first when validating a new process policy, then switch to `block` after the allowed process list is confirmed.

```yaml
policy: whitelist
process:
  enable: true
  mode: block
  target: host
  allow:
    - bash
    - sh
```

!!! warning

    Process blocking currently works as a whitelist policy. If the global `policy` is not `whitelist`, the process LSM program allows execution.

## Policy Modes

### Blacklist Mode (Default)

In blacklist mode, process execution is allowed by default. The current process restriction does not define a process `deny` list.

### Whitelist Mode

In whitelist mode, process execution is denied by default. Only process names in the `allow` list are permitted. Entries are matched against executable basenames, such as `bash` or `python3`.

## Configuration Map Structure

The process restriction uses BPF maps to store configuration:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-4 | 4 bytes | mode | Monitor(0) or Block(1) mode |
| 4-8 | 4 bytes | target | Host(0) or Container(1) |
| 8-12 | 4 bytes | policy | Blacklist(0) or Whitelist(1) |

## LSM Hooks

Process restriction uses the following LSM hooks:

- `bprm_check_security`: Triggered before a new executable is committed.

The process audit path also attaches `sched_process_fork` and `sched_process_exec` tracepoints for event collection.
