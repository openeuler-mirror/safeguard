# Current configuration options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable network restrictions. Default is `false`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, events are only logged. If `block` is specified, network access is blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction to the host-wide. Selecting `container` will apply the restriction only to containers. |
| `cidr` | List containing the following sub-keys:<br><li>`allow: [cidr list]`</li><li>`deny: [cidr list]`</li>| Allow or Deny CIDRs. |
| `domain` | List containing the following sub-keys:<br><li>`allow: [domain list]`</li><li>`deny: [domain list]`</li>| Allow or Deny Domains. |
| `command` | List containing the following sub-keys:<br><li>`allow: [command list]`</li><li>`deny: [command list]`</li>| Allow or Deny commands. |
| `uid` | List containing the following sub-keys:<br><li>`allow: [uid list]`</li><li>`deny: [uid list]`</li>| Allow or Deny uids. |
| `gid` | List containing the following sub-keys:<br><li>`allow: [gid list]`</li><li>`deny: [gid list]`</li>| Allow or Deny gids. |

Set `enable: true` before applying the policy. If `enable` is omitted, safeguard keeps the network restriction module disabled even when `mode`, `cidr`, `domain`, `command`, `uid`, or `gid` are configured.

```yaml
network:
  enable: true
  mode: block
  target: host
```
