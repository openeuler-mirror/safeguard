# Controller Architecture

## Components

### Service Layer
- Orchestrates whitelist generation
- Manages collector lifecycle

### Collector Interface
```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

### Model Package
- `HostSnapshot`: Raw host data
- `WhitelistModel`: Transformed configuration

## Data Flow

```
Host Data → Collector → HostSnapshot → BuildWhitelist → WhitelistModel → YAML
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
3. Create custom renderers for output formats
