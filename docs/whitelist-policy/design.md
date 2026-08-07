# Whitelist Policy Design Document

## Architecture Overview

The whitelist policy system consists of three layers:

```
┌─────────────────────────────────────────────────┐
│                  CLI Layer                       │
│  safeguard controller generate                  │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│               Service Layer                      │
│  orchestrates collection and generation         │
└─────────────────────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │Collector │  │  Model   │  │ Renderer │
    │  Layer   │  │  Layer   │  │  Layer   │
    └──────────┘  └──────────┘  └──────────┘
```

## Collector Interface

```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

### Implementations

A single concrete type, `SnapshotCollector`, merges data from several host sources into one `HostSnapshot`:

| Source | Path | Output |
|-----------|--------|--------|
| passwd | /etc/passwd | User accounts |
| proc | /proc/* | Running processes |
| network | /proc/net plus host interfaces | Network CIDRs |

## Model Transformation

The `BuildWhitelist` function transforms raw data:

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel
```

### Deduplication

- `uniqueStrings()` removes duplicate strings
- `uniqueUints()` removes duplicate uints

## Policy Enforcement Flow

```
Config → BPF Maps → LSM Hooks → Kernel Enforcement
```

## Default Outputs

`safeguard controller generate` writes `demo-whitelist.yaml` and `demo-whitelist-report.json` by default. The CLI can override them with `--output` and `--report`.

### Policy Modes

| Mode | Behavior |
|------|----------|
| blacklist | Allow all, block denied |
| whitelist | Block all, allow permitted |
