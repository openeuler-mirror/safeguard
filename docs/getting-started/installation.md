# Installation

## Requirements

* Linux Kernel >= 5.13.0
  * BTF(`CONFIG_DEBUG_INFO_BTF`) must be enabled.
  * BPF LSM(`CONFIG_BPF_LSM`) must be enabled.
  * The active LSM list(`CONFIG_LSM` or the `lsm=` boot parameter) must include `bpf`.

### Kernel Configuration

The kernel must have been compiled with the following flags set:

```shell
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
```

Kernel compile flags can usually be checked by looking at `/proc/config.gz` or `/boot/config-<kernel-version>`.

Also, the active LSM list must contain `bpf`. This can be controlled by boot parameters as follows:

```shell
$ cat /etc/default/grub
...
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
...
```

Finally, refresh grub configuration with the command used by your distribution.

```shell
sudo update-grub
# or
sudo update-grub2
```

### Linux distributions and supported kernels

| Distro Name | Distro Version | Kernel Version |
|:-----------:|:--------------:|:--------------:|
| Ubuntu | >= 20.10 | 5.8+ |
| Fedora | >= 33 | 5.8+ |

## Install

Download release artifacts from the AtomGit project release page:

```text
https://atomgit.com/openeuler/safeguard/releases
```

Or build safeguard locally from source:

```shell
$ make libbpf-static
$ make build

$ sudo ./build/safeguard --config config/safeguard.yml #|grep BLOCK
```
