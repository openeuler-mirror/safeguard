# safeguard: KRSI(eBPF+LSM) based Linux security auditing tool

safeguard is a Linux audit and observer tool based on eBPF.
Security events can be audited and blocked based on the container of the process, and restrictions can be applied to container environments.

# Features

* Audit and control for network, file access, mount, and process events
* Monitor and block modes
* Host-wide and container-only restriction targets
* Network Access Control
* File Access Control
* Mount Access Control
* Process Access Control
* Whitelist configuration generation with controller

# Build

See [INSTALL.md](INSTALL.md) for build dependencies and kernel requirements.
Build libbpf first, then build the safeguard binary.

```shell
$ git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
# $ vagrant up && vagrant reload
# $ vagrant ssh

$ make libbpf-static
$ make build

sudo ./build/safeguard --config config/safeguard.yml
```



# LICENSE

safeguard's userspace program is licensed under Apache License 2.0 License.  
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).  
