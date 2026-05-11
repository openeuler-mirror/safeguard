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

```bash
culinux controller generate --output whitelist.yaml --report report.json
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

## Applying Configuration

```bash
culinux --config whitelist.yaml
```

## Mode Comparison

| Aspect | Monitor | Block |
|--------|---------|-------|
| Logging | All events | Violations only |
| Action | Log only | Prevent access |
| Use case | Testing | Production |
