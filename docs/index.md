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

# Documentation

## Getting Started

- [Overview](./getting-started/overview.md) - Introduction to safeguard capabilities
- [Quick Start](./getting-started/quickstart.md) - Get started in 5 minutes
- [Installation](./getting-started/installation.md) - Install and build instructions

## Configuration

- [Configuration Reference](./configuration/configuration.md) - Complete configuration options
- [Network Restriction](./configuration/network-restriction/configuration.md) - Network access control
- [File Access Restriction](./configuration/file-access-restriction/configuration.md) - File access control
- [Mount Restriction](./configuration/mount-restriction/configuration.md) - Mount operation control
- [Process Restriction](./configuration/process-restriction/configuration.md) - Process execution control
- [DNS Proxy](./configuration/dns_proxy.md) - DNS proxy configuration

## Controller

- [Architecture](./controller/architecture.md) - Controller architecture overview
- [Code Walkthrough](./controller/code-walkthrough.md) - Code structure and data flow
- [Extension Guide](./controller/extension-guide.md) - How to extend the controller

## Whitelist Policy

- [Design](./whitelist-policy/design.md) - Whitelist policy design document
- [User Manual](./whitelist-policy/user-manual.md) - How to use whitelist policies

## Use Cases

- [Prevent SSRF](./use-cases/prevent-ssrf.md) - Block cloud metadata access
- [Prevent Container Breakout](./use-cases/prevent-container-breakout.md) - Restrict container escape vectors

## Development

- [Build](./development/build.md) - Build and test instructions
- [Setup](./development/setup.md) - Development environment setup

## Reference

- [API Reference](./api-reference.md) - Go package API documentation
- [Troubleshooting](./troubleshooting.md) - Common issues and solutions

# LICENSE

safeguard's userspace program is licensed under Apache License 2.0 License.
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).
