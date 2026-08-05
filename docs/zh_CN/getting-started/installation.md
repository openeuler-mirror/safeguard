# 安装

## 系统要求

| 要求 | 说明 |
|------|------|
| 操作系统 | Linux（内核 >= 5.13） |
| 内核配置 | BPF LSM 支持（`CONFIG_BPF_LSM=y`） |
| 内核配置 | BTF 支持（`CONFIG_DEBUG_INFO_BTF=y`） |
| 权限 | root |
| 架构 | x86_64、aarch64 |

## RPM 包安装

从 AtomGit release 页面下载对应版本的 RPM 包：

```
https://atomgit.com/openeuler/safeguard/releases
```

安装：

```bash
yum install ./safeguard-*.rpm
```

启动：

```bash
sudo safeguard --config /etc/safeguard/safeguard.yml
```

## 源码编译

### 编译依赖

源码构建至少需要 Go、gcc/make、clang/llvm、bpftool、libelf 和 zlib。openEuler/RHEL 系发行版可参考：

```bash
sudo yum install -y git golang make gcc clang llvm bpftool elfutils-devel zlib-devel
```

### 内核配置

safeguard 依赖 BPF LSM，建议使用 Linux Kernel >= 5.13.0。内核编译时必须开启以下内核选项：

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
```

`CONFIG_LSM` 必须包含 `bpf`，运行时 LSM 顺序也需要启用 `bpf`。可以通过以下引导参数进行控制：

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
```

修改后刷新 grub 配置：

```bash
sudo update-grub
```

### 编译步骤

```bash
git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
make libbpf-static
make build
```

### 验证

```bash
sudo ./build/safeguard --config config/safeguard.yml
```

## 使用 Vagrant 开发环境

```bash
git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
vagrant up && vagrant reload
vagrant ssh
cd /vagrant/safeguard
make libbpf-static
make build
```

## 下一步

- [快速开始](./quickstart.md)：编写第一个配置并运行
- [配置说明](../configuration/configuration.md)：完整配置项参考
