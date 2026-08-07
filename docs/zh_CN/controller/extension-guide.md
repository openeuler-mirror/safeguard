# Controller 扩展指南

## 添加自定义采集器

实现 `SnapshotCollector` 接口：

```go
type MyCollector struct {
    // 自定义字段
}

func (c *MyCollector) Collect() (model.HostSnapshot, error) {
    var snapshot model.HostSnapshot
    snapshot.Hostname = "my-host"
    snapshot.Accounts = []model.Account{...}
    return snapshot, nil
}
```

### 注册自定义采集器

```go
service := Service{
    Collector: &MyCollector{},
    Now:       time.Now,
}
```

## 扩展白名单模型

### 第一步：添加字段

在 `WhitelistModel` 结构体中添加字段：

```go
type WhitelistModel struct {
    // 已有字段...
    MyCustomField []string
}
```

### 第二步：更新 BuildWhitelist

```go
func BuildWhitelist(snapshot HostSnapshot, now time.Time) WhitelistModel {
    // 已有逻辑...
    model.MyCustomField = extractCustomField(snapshot)
    return model
}
```

### 第三步：添加渲染

```go
func BuildConfig(w WhitelistModel, mode string) config.Config {
    cfg := config.DefaultConfig()
    // 将白名单字段映射到 safeguard 配置
    return *cfg
}
```

## 自定义输出格式

为新的报告格式创建渲染函数：

```go
func MarshalConfigJSON(w WhitelistModel) ([]byte, error) {
    return json.MarshalIndent(w, "", "  ")
}
```

## 测试扩展

为每个组件编写单元测试：

```go
func TestMyCollector_Collect(t *testing.T) {
    c := &MyCollector{}
    snapshot, err := c.Collect()
    require.NoError(t, err)
    assert.NotEmpty(t, snapshot.Hostname)
}
```

## 采集器设计原则

1. **幂等性**：多次调用 `Collect()` 应返回相同结果（在主机状态不变时）
2. **容错性**：单个采集源失败不应影响其他采集器
3. **最小权限**：只采集白名单生成所需的最少数据
4. **可测试性**：采集逻辑应可通过 mock 进行单元测试

## 添加新的限制模块支持

1. 在 `HostSnapshot` 中添加对应的数据字段
2. 在 `WhitelistModel` 中添加对应的白名单字段
3. 在 `BuildWhitelist` 中添加转换逻辑
4. 在 `BuildConfig` 中添加配置映射
5. 编写单元测试覆盖新增逻辑
