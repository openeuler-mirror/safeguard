# Overview

safeguard detects and controls four types of security events:

- [Network Access](../configuration/network-restriction/configuration.md)
- [File Access](../configuration/file-access-restriction/configuration.md)
- [Mount](../configuration/mount-restriction/configuration.md)
- [Process](../configuration/process-restriction/configuration.md)

safeguard can choose between the following restriction targets:

- Host-wide
- Container Only

safeguard can be run in two modes:

- Monitor Mode
- Block Mode

safeguard configuration is organized by top-level YAML sections:

- `policy` selects global blacklist or whitelist behavior.
- `network`, `files`, `mount`, and `process` configure each restriction module.
- `dns_proxy` and `log` configure DNS forwarding and audit log output.

Each restriction module is disabled by default. Set `enable: true` in the module before applying its rules.

# Features

- Restriction rules can be created based on various process contexts
    - Command name
    - UID / GID where supported
- Monitoring and Blocking modes
    - Two modes are available: monitoring mode, which monitors and logs events, and blocking mode, which blocks events
- For Containers
    - Restrictions can be applied to containers only

# DEMO

[![asciicast](https://asciinema.org/a/475371.svg)](https://asciinema.org/a/475371)
