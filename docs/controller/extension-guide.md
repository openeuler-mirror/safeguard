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
    snapshot.Accounts = []model.Account{...}

    return snapshot, nil
}
```

### Register Custom Collector

```go
service := Service{
    Collector: &MyCollector{},
    Now:       time.Now,
}
```

## Extending Whitelist Model

### Step 1: Add Field

```go
type WhitelistModel struct {
    // existing fields...
    MyCustomField []string
}
```

### Step 2: Update BuildWhitelist

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel {
    // existing logic...
    model.MyCustomField = extractCustomField(snapshot)
    return model
}
```

### Step 3: Add Rendering

```go
func MarshalConfigYAML(w WhitelistModel, mode string) ([]byte, error) {
    // Add your field to YAML output
}
```

## Custom Output Formats

Create new renderer for different formats:

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
