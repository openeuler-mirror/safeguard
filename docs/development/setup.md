# Setup

The development VM follows the same runtime requirements as a manual install:

* Linux Kernel >= 5.13.0.
* BTF support enabled with `CONFIG_DEBUG_INFO_BTF=y`.
* BPF LSM enabled with `CONFIG_BPF_LSM=y`.
* The active LSM list includes `bpf`, for example `lsm=lockdown,yama,apparmor,bpf`.

See Vagrantfile provisioning settings for the package list and boot parameter setup.
The VM installs the Ubuntu equivalents of the manual build dependencies, including Go, build-essential, clang/llvm, libbpf, libelf, zlib, linux-tools, and gotestsum.

```shell
$ git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
$ vagrant up && vagrant reload
$ vagrant ssh
```

## Manual Setup (Without Vagrant)

If you prefer not to use Vagrant, install the following dependencies manually:

### Kernel Requirements

Verify your kernel version and BPF LSM support:

```shell
$ uname -r
5.15.0-generic

$ cat /sys/kernel/security/lsm | tr ',' '\n' | grep bpf
bpf
```

If BPF LSM is not enabled, add `bpf` to the `lsm=` kernel boot parameter and reboot.

### Package Installation (openEuler/RHEL)

```shell
$ sudo dnf install golang clang llvm elfutils-libelf-devel zlib-devel bpftool
```

### Package Installation (Ubuntu/Debian)

```shell
$ sudo apt install golang clang llvm libelf-dev zlib1g-dev linux-tools-common
```

## Development Workflow

1. Clone the repository with submodules: `git clone --recursive ...`
2. Build libbpf: `make libbpf-static`
3. Build the project: `make build`
4. Run tests: `make test`
5. Run the binary: `sudo ./output/safeguard --config config/safeguard.yml`

## IDE Configuration

For Go development, the following tools are recommended:

- `gopls` — Go language server
- `golangci-lint` — Go linter
- `goimports` — Import management

Ensure your editor is configured to use the CGO flags when working with audit packages.
