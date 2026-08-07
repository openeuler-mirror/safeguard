# 编译

在安装 `INSTALL.md` 中列出的依赖后，或进入 Vagrant 虚拟机后，从仓库根目录执行构建。

`make libbpf-static` 准备 vendored libbpf 静态库，`make build` 编译 eBPF 对象和 safeguard 二进制。

```bash
$ vagrant ssh

$ cd /vagrant/safeguard
$ make libbpf-static
$ make build
```

# 测试

```bash
$ make test
```

CGO 包测试需要额外标志：

```bash
$ CGO_CFLAGS="-I$(pwd)/output" CGO_LDFLAGS="-lelf -lz $(pwd)/output/libbpf.a" go test ./pkg/audit/...
```

# 开发环境设置

开发虚拟机的运行时要求与手动安装相同：

* Linux Kernel >= 5.13.0
* BTF 支持（`CONFIG_DEBUG_INFO_BTF=y`）
* BPF LSM 启用（`CONFIG_BPF_LSM=y`）
* 活跃 LSM 列表包含 `bpf`，例如 `lsm=lockdown,yama,apparmor,bpf`

Vagrantfile 中包含了包列表和引导参数设置。虚拟机安装了 Ubuntu 等效的手动构建依赖，包括 Go、build-essential、clang/llvm、libbpf、libelf、zlib、linux-tools 和 gotestsum。

```bash
$ git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
$ vagrant up && vagrant reload
$ vagrant ssh
```

## 编译加速

如果已有 libbpf 静态库，可以跳过 `make libbpf-static`：

```bash
$ make build
```

## 交叉编译

暂不支持交叉编译，safeguard 需要在目标架构上编译。
