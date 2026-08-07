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
Host Data → Collector → HostSnapshot → BuildWhitelist → WhitelistModel → YAML config
                                                              └──────────────→ JSON report
```

## Collectors

A single concrete type, `SnapshotCollector`, merges data from several host sources into one `HostSnapshot`:

| Source | Path | Output |
|--------|------|--------|
| passwd | /etc/passwd | User accounts |
| proc | /proc | Running processes |
| network | /proc/net plus host interfaces | Network CIDRs |

## Extension Points

1. Implement `SnapshotCollector` for new data sources
2. Add fields to `WhitelistModel` for new config types
3. Extend `render.BuildConfig` and the report renderer for new output fields
