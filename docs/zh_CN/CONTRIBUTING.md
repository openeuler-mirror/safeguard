# 贡献指南

## 开发环境设置

### 前置要求
- Go 1.21+
- Linux 内核 5.10+
- BPF 开发工具

### 编译

```bash
make build
```

### 测试

```bash
# 单元测试
make test

# 集成测试（需要 root 权限）
sudo make test-integration
```

## 代码风格

- 遵循 Go 标准格式化（`gofmt`）
- 使用有意义的变量名
- 为新功能添加测试

## Pull Request 流程

1. 从 master 创建功能分支
2. 编写聚焦的提交，附带清晰的提交信息
3. 确保测试通过
4. 如需要，更新文档
5. 提交 PR 并描述变更内容

## 项目结构

```
pkg/
├── audit/          # 审计模块（文件、网络、挂载、进程）
├── bpf/            # BPF 程序
├── config/         # 配置处理
├── controller/     # 白名单生成
│   ├── collector/  # 主机数据采集
│   ├── model/      # 数据结构
│   └── render/     # 输出渲染
└── log/            # 日志工具
```

## 添加新功能

### 新采集器
1. 实现 `SnapshotCollector` 接口
2. 在 `collector_test.go` 中添加测试
3. 在 `SnapshotCollector` 组合中注册

### 新策略字段
1. 添加到 `WhitelistModel` 结构体
2. 更新 `BuildWhitelist` 函数
3. 添加 YAML 渲染
4. 如需要，更新 BPF 程序
