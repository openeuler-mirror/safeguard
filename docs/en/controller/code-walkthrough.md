# safeguard controller - Code Walkthrough

## Overview

The `pkg/controller` module generates whitelist configurations by collecting host data (users, processes, network) and automatically generating the YAML configuration files required by safeguard, with optional JSON report output.

## Project Structure

```
pkg/controller/
├── model/                    # Data model layer
│   ├── types.go              # Struct definitions
│   └── build.go              # Whitelist building logic
├── collector/                # Data collection layer
│   ├── passwd.go             # /etc/passwd parsing
│   ├── network.go            # Network information collection
│   ├── proc.go               # Process information collection
│   └── snapshot.go           # Collector entry point
├── render/                   # Rendering output layer
│   └── render.go             # YAML/JSON output
├── processcheck/             # Process whitelist checking
│   └── matcher.go            # Whitelist matcher
├── service.go                # Service layer (orchestrates all layers)
└── command.go                # CLI command definition
```

## Data Flow Architecture

```
CLI Entry (safeguard controller generate)
    │
    ▼
command.go ──parse --mode/--output/--report──▶ Service.Generate()
    │
    ▼
service.go
    ├─ Collector.Collect()  → HostSnapshot
    ├─ BuildWhitelist()     → WhitelistModel
    ├─ MarshalConfigYAML()  → YAML bytes
    ├─ WriteFile()          → Save YAML config
    ├─ MarshalReportJSON()  → JSON bytes (optional)
    └─ WriteFile()          → Save JSON report (optional)
    │
    ▼
collector/ ◀───────────── model/ ◀───────────── render/
```

The CLI defaults to `demo-whitelist.yaml` and `demo-whitelist-report.json`. Override with `--output` and `--report`. The generated config can be applied via `safeguard --config demo-whitelist.yaml`.
