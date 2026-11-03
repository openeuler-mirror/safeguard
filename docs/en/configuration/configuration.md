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
| `log` | Map containing the following sub-keys: <br><li>`level: [TRACE|DEBUG|INFO]`</li><li>`format: [json|text]`</li><li>`output: <path>`</li><li>`max_size:`: Maximum size to rotate (MB). Default: 100MB</li><li>`max_age`: Backup retention in days. Default: 0 (no age-based removal)</li><li>`labels`: Key / Value to be added to the log.</li>| Log configuration. |

## Validate before deployment

```sh
safeguard controller validate --config config/whitelist.yaml
```

This checks configuration syntax and settings without collecting host data, loading BPF, or requiring root. It does not test DNS reachability, kernel support, or whether the policy is sufficient for your workload.

- Supply exactly one non-null YAML document. Unknown fields and duplicate keys are rejected, including in disabled sections; YAML anchors and merge keys remain supported.
- Use `files` and `dns_proxy` as the section names. Process rules support `process.allow`; `process.deny` is unsupported.
- `policy` must be `blacklist` or `whitelist`. Enabled modules require `mode: monitor|block` and `target: host|container`.
- When network restrictions are enabled, CIDR allow/deny entries must parse, domain entries must not be empty or whitespace-only, and UID/GID allow/deny entries must fit `0`–`4294967295`.
- `log.max_size` and `log.max_age` must be nonnegative. Both default to `0` in the config: the rotation library uses 100 MB for zero size and does not remove backups by age when age is zero.

Validation failures return a nonzero command exit status and identify the input file and failed stage. On upgrade, correct misspelled or obsolete keys that older versions silently ignored; do not remove a rule merely to suppress an error.

## Example Configuration

```yaml
policy: blacklist
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow:
      - 0.0.0.0/0
files:
  enable: true
  mode: block
  target: host
  allow:
    - /
mount:
  enable: false
process:
  enable: false
dns_proxy:
  enable: false
log:
  level: INFO
  format: json
  output: /var/log/safeguard.log
```
