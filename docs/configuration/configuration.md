# Configuration

safeguard's configuration file is a YAML file containing top-level configuration sections. Each restriction section is a YAML map with its own `enable`, `mode`, `target`, and rule fields.

## Current configuration options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `policy` | Enum with the following possible values: `blacklist`, `whitelist` | Global policy mode. Default is `blacklist`. |
| `network` | Map (see [Network Restriction](./network-restriction/configuration.md)) | Rule for network restrictions. |
| `files` | Map (see [File Access Restriction](./file-access-restriction/configuration.md)) | Rule for file access restrictions. |
| `process` | Map (see [Process Restriction](./process-restriction/configuration.md)) | Rule for process restrictions. |
| `mount` | Map (see [Mount Restriction](./mount-restriction/configuration.md)) | Rule for mount restrictions. |
| `dns_proxy` | Map (see [DNS Proxy](./dns_proxy.md)) | DNS proxy configuration. |
| `log` | Map containing the following sub-keys: <br><li>`level: [DEBUG|INFO|WARN|ERROR]`</li><li>`format: [json|text]`</li><li>`output: <path>`</li><li>`max_size:`: Maximum size to rotate (MB). Default: 100MB</li><li>`max_age`: Period for which logs are kept. Default: 365</li><li>`labels`: Key / Value to be added to the log.</li>| Log configuration. |
