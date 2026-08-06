# Whitelist Policy User Manual

## Overview

The whitelist policy feature enables automatic generation of security configurations
based on the current host state. This provides a secure-by-default approach.

## Configuration

### Policy Modes

| Mode | Description |
|------|-------------|
| blacklist | Allow all except denied items (default) |
| whitelist | Block all except allowed items |

```yaml
policy: whitelist
```

### Generating Whitelist

The examples below use the installed `safeguard` command.

```bash
safeguard controller generate
```

By default, the command writes `demo-whitelist.yaml` and `demo-whitelist-report.json`.
Use `--output` and `--report` when custom file names are needed:

```bash
safeguard controller generate --output whitelist.yaml --report report.json
```

## Generated Components

### Network
- CIDR ranges from interfaces
- Allowed UIDs/GIDs
- Running process commands

### Process
- Currently running executables
- User accounts

### File Access
- Home directories
- Executable paths

### Report
- JSON summary written to `demo-whitelist-report.json` by default

## Applying Configuration

```bash
safeguard --config demo-whitelist.yaml
```

If `--output whitelist.yaml` was used during generation, apply that file instead.

## Mode Comparison

| Aspect | Monitor | Block |
|--------|---------|-------|
| Logging | All events | Violations only |
| Action | Log only | Prevent access |
| Use case | Testing | Production |
