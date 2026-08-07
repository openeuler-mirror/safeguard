# Controller Architecture

## Components

### Service Layer
- Orchestrates whitelist generation
- Manages collector lifecycle
- Writes the generated YAML config and optional JSON report

### Collector Interface
```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

### Model Package
- `HostSnapshot`: Raw host data
- `WhitelistModel`: Transformed configuration
- `BuildWhitelist`: Deduplicates collected host data before rendering

## Data Flow

```
Host Data -> Collector -> HostSnapshot -> BuildWhitelist -> WhitelistModel -> YAML config
                                                              |-> JSON report
```

## Collectors

| Collector | Source | Output |
|-----------|--------|--------|
| PasswdCollector | /etc/passwd | User accounts |
| ProcCollector | /proc | Running processes |
| NetworkCollector | /sys/class/net | Network interfaces |

## Extension Points

1. Implement `SnapshotCollector` for new data sources
2. Add fields to `WhitelistModel` for new config types
3. Extend `render.BuildConfig` and the report renderer for new output fields

## Policy Modes

The controller supports two policy modes:

| Mode | Behavior |
|------|----------|
| blacklist | Allow all, block only denied items |
| whitelist | Block all, allow only permitted items |

The default output files are `demo-whitelist.yaml` and `demo-whitelist-report.json`. Override with `--output` and `--report`.
