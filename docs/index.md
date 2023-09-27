# safeguard: KRSI(eBPF+LSM) based Linux security auditing tool

safeguard is KRSI(eBPF+LSM) based Linux security auditing tool.  
Security events can be audited and blocked based on the container of the process, and restrictions can be applied to container environments.

# Features

* Restriction rules based on process context, such as command name or UID and more
* Restrictions limited to containers
* Network Access Control
* File Access Control
* Restictions bind mounts from host filesystem to containers

# LICENSE

safeguard's userspace program is licensed under Apache License 2.0 License.  
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).  
