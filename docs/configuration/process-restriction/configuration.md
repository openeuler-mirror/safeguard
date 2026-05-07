# Current configuration options

Linux Kernel >= 5.13 is required to use this option.

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable restrictions or not. Default is `true`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, events are only logged. If `block` is specified, network access is blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction to the host-wide. Selecting `container` will apply the restriction only to containers. |
| `deny` | A list of allow file paths | |

!!! warning

    Currently file access restrictions cannot be based on process context (command name, UID, etc).  
    This is because the eBPF Program size becomes too large, and it is failed pass by the eBPF Verifier's limitations.  
    If you can create a better eBPF program, please contribute!
## Policy Modes

### Blacklist Mode (Default)

In blacklist mode, all processes are allowed by default. Only processes in the `deny` list will be blocked.

### Whitelist Mode

In whitelist mode, all processes are denied by default. Only processes in the `allow` list will be permitted.

## Configuration Map Structure

The process restriction uses BPF maps to store configuration:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-4 | 4 bytes | mode | Monitor(0) or Block(1) mode |
| 4-8 | 4 bytes | target | Host(0) or Container(1) |
| 8-12 | 4 bytes | policy | Blacklist(0) or Whitelist(1) |

## LSM Hooks

Process restriction uses the following LSM hooks:

- `sched_process_fork`: Triggered when a new process is forked
- `sched_process_exec`: Triggered when a process executes a new program
