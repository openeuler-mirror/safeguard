# Whitelist Policy User Manual

## Overview

The whitelist policy feature enables automatic generation of security configurations
based on the current host state. Review the result before enforcing it; generation
defaults to monitor mode, which does not block violations.

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
- Host addresses from interfaces and remote addresses from `/proc/net`
- Allowed UIDs/GIDs from accounts and running processes
- An empty command allow list

### Process
- Names derived from currently running executables or process commands

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
| Effect | Observe policy violations | Enforce the policy |
| Action | Log only | Prevent access |
| Typical use | Review before enforcement | Enforcement after review |
