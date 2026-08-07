# Installing safeguard

## Build Dependencies

Source builds require at least Go, gcc/make, clang/llvm, bpftool, libelf, and zlib. For openEuler/RHEL-based distributions:

```shell
sudo yum install -y git golang make gcc clang llvm bpftool elfutils-devel zlib-devel
```

## Kernel Configuration

safeguard depends on BPF LSM and requires Linux Kernel >= 5.13.0. The following kernel options must be enabled:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
```

Check kernel compile flags via `/proc/config.gz` or `/boot/config-<kernel-version>`.

Additionally, `CONFIG_LSM` must include `bpf`, and the runtime LSM order must also enable `bpf`. This can be controlled via the boot parameter:

```shell
$ cat /etc/default/grub
...
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
...
```

After modification, refresh the grub configuration for your distribution:

```shell
sudo update-grub
# or
sudo update-grub2
```

## Build from Source

```shell
git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
make libbpf-static
make build
```

## Verify

```shell
sudo ./build/safeguard --config config/safeguard.yml
```

## RPM Installation

Download the RPM package from the AtomGit release page:

```
https://atomgit.com/openeuler/safeguard/releases
```

```shell
yum install ./safeguard-*.rpm
sudo safeguard --config /etc/safeguard/safeguard.yml
```
