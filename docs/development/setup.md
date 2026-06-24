# Setup

The development VM follows the same runtime requirements as a manual install:

* Linux Kernel >= 5.13.0.
* BTF support enabled with `CONFIG_DEBUG_INFO_BTF=y`.
* BPF LSM enabled with `CONFIG_BPF_LSM=y`.
* The active LSM list includes `bpf`, for example `lsm=lockdown,yama,apparmor,bpf`.

See Vagrantfile provisioning settings for the package list and boot parameter setup.

```shell
$ git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
$ vagrant up && vagrant reload
$ vagrant ssh
```
