# API Reference

## Audit runtime lifecycle

```shell
sudo safeguard --config /etc/safeguard/safeguard.yaml --startup-timeout 30s --shutdown-timeout 10s
# After all enabled audit event buffers start: All configured audit modules started.
# Ctrl-C (SIGINT), followed by successful shutdown: exit 0.
safeguard --config /missing/safeguard.yaml
# Configuration failure: exit 1; no BPF module is loaded.
```

- `--startup-timeout` defaults to `30s`; `0` disables the startup deadline. Negative values are rejected.
- `--shutdown-timeout` defaults to `10s`; `0` selects that default. Negative values are rejected.
- A startup failure or consumer panic cancels peer audit tasks. Startup/parent deadlines and shutdown timeouts return an error (CLI exit 1).
- An explicit context cancellation or SIGINT returns success if cleanup completes without another error. SIGTERM has no custom handler.
- If all modules are disabled, validated configuration exits successfully before root, LSM, or logging setup; no readiness notification is sent.
- Readiness covers enabled modules' synchronous load, map, attach, and event-buffer initialization. It does not verify asynchronous DNS binding/resolution.
- Shutdown stops producers and waits for handlers already processing events before releasing modules. It does not guarantee delivery of records still inside libbpf queues.
- Cancellation is cooperative between startup operations. Go callbacks and C/kernel calls already in progress cannot be forcibly interrupted; the shutdown budget bounds coordinator waiting.
- DNS background workers retain their existing separate lifecycle; these guarantees cover coordinated audit tasks and their event consumers.

Embedding applications may use `audit.NewApp(version, audit.WithReadyNotification(func(context.Context) error))`. A notification error/panic cancels audit tasks; a blocked notification is subject to the shutdown budget. `helpers.StageError` supports `errors.As` for module/stage diagnostics and preserves the underlying cause via `errors.Is`.

## Controller Package

### CLI

```shell
safeguard controller generate --output demo-whitelist.yaml --report demo-whitelist-report.json --mode monitor
```

### Service

```go
type Service struct {
    Collector SnapshotCollector
    Now       func() time.Time
}

func NewService() Service
func (s Service) Generate(options GenerateOptions) error
```

### GenerateOptions

```go
type GenerateOptions struct {
    Mode       string  // "monitor" or "block"
    OutputPath string  // YAML config output path
    ReportPath string  // optional JSON report output path
}
```

## Collector Package

### SnapshotCollector Interface

```go
type SnapshotCollector interface {
    Collect() (model.HostSnapshot, error)
}
```

### Implementations

- `PasswdCollector`: Reads /etc/passwd
- `ProcCollector`: Reads /proc filesystem
- `NetworkCollector`: Gathers network info

## Model Package

### HostSnapshot

```go
type HostSnapshot struct {
    Hostname         string
    CIDRs            []string
    Accounts         []Account
    UIDs             []uint
    GIDs             []uint
    RunningProcesses []RunningProcess
    ExecutablePaths  []string
    Warnings         []string
}
```

### WhitelistModel

```go
type WhitelistModel struct {
    Metadata Metadata
    Network  NetworkWhitelist
    Accounts []Account
    Files    FileWhitelist
    Process  ProcessWhitelist
    Warnings []string
}
```

### BuildWhitelist

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel
```

## Render Package

```go
func BuildConfig(w WhitelistModel, mode string) config.Config
func MarshalConfigYAML(w WhitelistModel, mode string) ([]byte, error)
func MarshalReportJSON(w WhitelistModel) ([]byte, error)
func WriteFile(path string, data []byte) error
```
