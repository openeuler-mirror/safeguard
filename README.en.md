# safeguard: Linux security audit, control, and behavior analysis tools based on KRSI(eBPF+LSM)

safeguard is a Linux audit and observation tool based on eBPF. It can audit and block security operations, and apply restrictions to container environments. The project uses the libbpfgo library and implements top-level control in Go.

# Features

* Audit: Record network, file, mount, and process events within configured scope
* Control: Support network access, file access, mount, and process execution restrictions
* Policy: Support monitor/block modes, and host/container scope
* Whitelist: Automatically generate whitelist configuration via the controller module

![architecture](docs/architecture.png)

# Build

Build dependencies and kernel configuration are described in [INSTALL.md](INSTALL.md). Build libbpf first, then build the safeguard binary.

```shell
$ git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
# $ vagrant up && vagrant reload
# $ vagrant ssh

$ make libbpf-static
$ make build

$ sudo ./build/safeguard --config config/safeguard.yml
```

`config/safeguard.yml` is the default sample configuration in the source tree. Use a local file for ad-hoc testing, and use `whitelist.yaml` for controller-generated whitelist configs.

# Install

Download the RPM package for your version from the AtomGit release page:

```text
https://atomgit.com/openeuler/safeguard/releases
```

```shell
$ yum install ./safeguard-*.rpm
$ sudo safeguard --config /etc/safeguard/safeguard.yml
```

# Whitelist Policy

Use the controller module to automatically generate whitelist configuration:

```shell
# Generate whitelist configuration
$ sudo ./build/safeguard controller generate --output whitelist.yaml --report report.json

# Apply whitelist configuration
$ sudo ./build/safeguard --config whitelist.yaml
```

Whitelist mode configuration example:

```yaml
policy: whitelist  # blacklist (allow by default) or whitelist (block by default)

network:
  enable: true
  mode: block
  cidr:
    allow:
      - 127.0.0.1/8
      - 10.0.0.0/8
    deny: []

process:
  enable: true
  mode: block
  allow:
    - bash
    - python3
```

# configuration map
```shell
$ bpftool map update pinned /sys/fs/bpf/file_config key 00 00 00 00 value 01 00 00 00 00 00 00 00
```

# Project Features (some in development)

### Audit and Control
File:
- Track filesystem activity, including file open, close, read, write, and delete.
- Modify filesystem behavior, such as intercepting certain file operations or implementing custom security policies.
  Security policies:
    1. Intercept or redirect file operations: use eBPF to intercept read/write operations on sensitive files, or redirect access to certain files to other locations.
    2. Implement custom access control: use eBPF to check the identity, permissions, and environment of the accessor, then allow or deny access based on rules.
    3. Implement custom auditing and monitoring: use eBPF to record detailed information about operations on certain files, such as the operator, time, and content, and output this information to logs.

Process:
- Track process lifecycle, such as process creation, termination, scheduling, and context switching.
- Modify process behavior, such as injecting or modifying certain system calls, or implementing custom scheduling policies.

Network:
- Track network activity, such as packet sending, receiving, forwarding, and dropping.
- Modify network behavior, such as filtering or rewriting certain packets, or implementing custom routing policies.

### Behavior Analysis
- Collect and analyze filesystem performance, hotspots, and anomalies.
- Collect information to analyze process resource consumption, state changes, and dependencies.
- Collect information to analyze network traffic, latency, packet loss rate, and congestion.

### Host Management
Automatically build fine-grained asset information from a security perspective, supporting precise identification and dynamic perception of business-layer assets.
- Account display
- Port list
- Process list

### Risk Management
Precisely discover internal risks, quickly locate problems and effectively resolve security risks.
- Vulnerability detection
- Security patches
- Weak passwords
- System risks
- Account risks

### Intrusion Detection
Provide multi-anchor detection capabilities, able to perceive intrusion events in real-time and accurately.
- Brute force
- Abnormal login
- Reverse shell
- Local privilege escalation
- Backdoor detection, Web backdoor

# Development Roadmap

|           |                                     | 22.03 LTS SPx| 24.03 LTS | 24.03 SPx | Implemented |
|-|-|:-:|:-:|:-:|:-:|
| Control-Host rule settings | File operation interception | | | | ✓ |
| | Process interception (path hook) | ✓ | | | ✓ |
| | Network interception | | | | ✓ |
| Host Management | Account | ✓ | | | |
| | Port | ✓ | | | |
| | Process | ✓ | | | |
| Risk Management | Vulnerability detection | | | ✓ | |
| | Security patches | | | ✓ | |
| | Weak passwords | | | ✓ | |
| | System risks | | | ✓ | |
| | Account risks | | | ✓ | |
| Intrusion Detection | Brute force | | ✓ | | |
| | Abnormal login | | ✓ | | |
| | Reverse shell | | | ✓ | |
| | Local privilege escalation | | ✓ | | |
| | Backdoor detection, Web backdoor | | | ✓ | |
| Security Log | Audit log: file hook interception changed from path to inode | ✓ | | | ✓ |
| | Login log | ✓ | | | |
| | Account change log | | ✓ | | |
| Separation of powers | Separation of powers | | | | |

# LICENSE

safeguard's userspace program is licensed under Apache License 2.0 License.
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).
