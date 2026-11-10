# Controller Extension Guide

## Adding Custom Collectors

Implement the `SnapshotCollector` interface:

```go
type MyCollector struct {
    // your fields
}

func (c *MyCollector) Collect() (model.HostSnapshot, error) {
    var snapshot model.HostSnapshot

    // Collect your data
    snapshot.Hostname = "my-host"
    snapshot.Accounts = []model.Account{}

    return snapshot, nil
}
```

### Register Custom Collector

```go
service := controller.Service{
    Collector: &MyCollector{},
    Now:       time.Now,
}
```

Import `culinux/pkg/controller`, `culinux/pkg/controller/model`, and `time` for
these examples. `Service.Generate` requires a collector and clock.

The built-in collector returns errors for required hostname, account, process,
and interface data; unreadable `/proc/net` files produce report warnings.

## Extending Whitelist Model

### Step 1: Add Field

```go
type WhitelistModel struct {
    // existing fields...
    MyCustomField []string
}
```

### Step 2: Update BuildWhitelist

This sketch requires the new field and extraction function; retain existing mappings.

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel {
    // existing logic...
    result := WhitelistModel{} // preserve the existing field mappings here
    result.MyCustomField = extractCustomField(snapshot)
    return result
}
```

### Step 3: Add Rendering

```go
func BuildConfig(w WhitelistModel, mode string) config.Config {
    cfg := config.DefaultConfig()
    // Map your whitelist field into safeguard config
    return *cfg
}
```

## Custom Output Formats

Create new renderer functions for additional report formats:

```go
func MarshalConfigJSON(w WhitelistModel) ([]byte, error) {
    return json.MarshalIndent(w, "", "  ")
}
```

## Testing Extensions

Write unit tests for each component:

```go
func TestMyCollector_Collect(t *testing.T) {
    c := &MyCollector{}
    snapshot, err := c.Collect()
    require.NoError(t, err)
    assert.NotEmpty(t, snapshot.Hostname)
}
```
