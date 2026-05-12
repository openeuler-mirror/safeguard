# Contributing Guide

## Development Setup

### Prerequisites
- Go 1.21+
- Linux kernel 5.10+
- BPF development tools

### Build

```bash
make build
```

### Test

```bash
# Unit tests
make test

# Integration tests (requires root)
sudo make test-integration
```

## Code Style

- Follow Go standard formatting (`gofmt`)
- Use meaningful variable names
- Add tests for new functionality

## Pull Request Process

1. Create a feature branch from master
2. Make focused commits with clear messages
3. Ensure tests pass
4. Update documentation if needed
5. Submit PR with description of changes

## Project Structure

```
pkg/
├── audit/          # Audit modules (file, network, mount, process)
├── bpf/            # BPF programs
├── config/         # Configuration handling
├── controller/     # Whitelist generation
│   ├── collector/  # Host data collection
│   ├── model/      # Data structures
│   └── render/     # Output rendering
└── log/            # Logging utilities
```

## Adding New Features

### New Collector
1. Implement `SnapshotCollector` interface
2. Add tests in `collector_test.go`
3. Register in `SnapshotCollector` composite

### New Policy Field
1. Add to `WhitelistModel` struct
2. Update `BuildWhitelist` function
3. Add YAML rendering
4. Update BPF program if needed
