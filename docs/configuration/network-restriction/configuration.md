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

## CIDR Rules

CIDR rules control network access based on IP address ranges. Both IPv4 and IPv6 CIDRs are supported.

- `allow`: Connections matching these CIDRs are permitted
- `deny`: Connections matching these CIDRs are blocked

When `mode` is `block`, denied CIDR connections are blocked. When `mode` is `monitor`, all connections are logged.

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
      - 10.0.0.0/8
```

## Domain Rules

Domain rules control network access based on domain names. Requires DNS proxy or periodic name resolution.

```yaml
network:
  enable: true
  mode: block
  target: host
  domain:
    allow:
      - example.com
      - trusted.internal
    deny:
      - malicious.example.com
```

## Command Rules

Command rules control network access based on the executing process command name.

```yaml
network:
  enable: true
  mode: block
  target: host
  command:
    allow:
      - curl
      - wget
    deny:
      - nc
```

## UID/GID Rules

UID and GID rules control network access based on the user or group ID of the process.

```yaml
network:
  enable: true
  mode: block
  target: host
  uid:
    allow: [0, 1000]
    deny: [65534]
  gid:
    allow: [0, 1000]
```

## LSM Hooks

Network restriction uses the following LSM hooks:

- `socket_connect`: Triggered when a network connection is initiated
- `socket_bind`: Triggered when a socket is bound to an address

## Policy Modes

When `policy: whitelist` is set in the top-level configuration:

- `allow` lists are enforced (only listed items are permitted)
- `deny` lists are ignored

When `policy: blacklist` (default):

- `deny` lists are enforced (listed items are blocked)
- `allow` lists are used as exceptions to deny rules
