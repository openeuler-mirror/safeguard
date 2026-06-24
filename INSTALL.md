# 安装 safeguard

## 编译工具

源码构建至少需要 Go、gcc/make、clang/llvm、bpftool、libelf 和 zlib。openEuler/RHEL 系发行版可参考：

```shell
sudo yum install -y git golang make gcc clang llvm bpftool elfutils-devel zlib-devel
```

## 内核配置

safeguard 依赖 BPF LSM，建议使用 Linux Kernel >= 5.13.0。内核编译时必须开启以下内核选项：

```shell
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
```

内核编译标志可以通过查看 `/proc/config.gz` 或 `/boot/config-<kernel-version>` 来检查。

此外，`CONFIG_LSM` 必须包含 `bpf`，运行时 LSM 顺序也需要启用 `bpf`。可以通过以下引导参数进行控制：

```shell
$ cat /etc/default/grub
...
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
...
```

修改后需要按发行版刷新 grub 配置，例如：

```shell
sudo update-grub
# or
sudo update-grub2
```
