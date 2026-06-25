# safeguard: KRSI(eBPF+LSM) based Linux security auditing tool

safeguard is KRSI(eBPF+LSM) based Linux security auditing tool.  
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

# LICENSE

safeguard's userspace program is licensed under Apache License 2.0 License.  
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).  
