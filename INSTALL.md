# 安装 safeguard

## 编译工具

安装必要的编译工具，可能包括：
```
$ yum install libbpf-devel make clang llvm elfutils-libelf-devel bpftool bcc-tools bcc-devel dwarves
```

## 内核配置

内核编译时必须开启以下内核选项：

```shell
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIF_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
```

内核编译标志可以通过查看`/proc/config.gz`或`/boot/config-<Kernel-version>` 来检查。

此外，`CONFIG_LSM`标志必须包含`bpf`。可以通过以下引导参数进行控制：

```shell
$ cat /etc/default/grub
...
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
...
```
