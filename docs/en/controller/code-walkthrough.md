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
    ├─ MarshalReportJSON()  → JSON bytes (optional)
    ├─ WriteFile()          → Save YAML config
    └─ WriteFile()          → Save JSON report (optional)
```

When collection or rule conversion produces warnings, a report path is required so omitted rules remain visible.

The CLI defaults to `demo-whitelist.yaml` and `demo-whitelist-report.json`. Override with `--output` and `--report`. The generated config can be applied via `safeguard --config demo-whitelist.yaml`.

The YAML and optional report are encoded before either file is written. When warnings
exist, the report is written first and a report failure leaves the config untouched.
Otherwise YAML is written first and is not rolled back if the report write fails. `processcheck`
is a separate matching utility; it is not part of this generation flow and does
not represent kernel enforcement results.

## Review generation warnings

Generate a configuration and report in monitor mode first:

```sh
safeguard controller generate --mode monitor --output whitelist.yaml --report report.json
safeguard controller validate --config whitelist.yaml
python3 -c 'import json; print("\n".join(json.load(open("report.json"))["warnings"]))'
```

The report's `warnings` can identify malformed passwd entries by file and line,
processes with invalid identity fields, unreadable network tables, overlong file paths, process names containing slashes, root account homes, or entries exceeding
BPF map capacity. Network table open failures include the system error, helping
distinguish missing files from permission problems. Skipped or truncated entries are not replaced with broader
rules. Review the report and generated file, process, and network allow lists
against actual workload needs. Validation checks syntax and static constraints;
it does not prove coverage or kernel enforcement. Review monitoring results and
rule scope before deciding whether to use block mode.
