# API Reference

## Controller Package

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
    OutputPath string  // YAML output path
    ReportPath string  // JSON report path
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
func MarshalConfigYAML(w WhitelistModel, mode string) ([]byte, error)
func MarshalReportJSON(w WhitelistModel) ([]byte, error)
func WriteFile(path string, data []byte) error
```
