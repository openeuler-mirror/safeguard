#### Block dangerous commands in container

The `deny` list contains process command names that are blocked.

```yaml
process:
  enable: true
  mode: block
  target: container
  deny:
    - nmap
    - nc
    - curl
```

!!! example

    ```shell
    # docker run --rm -it ubuntu:latest nmap 10.0.0.1
    nmap: operation not permitted
    ```

#### Allow only specific commands

Use `allow` list with `policy: whitelist` to restrict to only permitted commands:

```yaml
policy: whitelist

process:
  enable: true
  mode: block
  target: host
  allow:
    - bash
    - ls
    - cat
    - grep
    - python3
```

#### Monitor process execution

Use monitor mode to observe process events before blocking:

```yaml
process:
  enable: true
  mode: monitor
  target: host
  deny:
    - nmap
    - nc
    - wget
```

!!! note

    In monitor mode, all process execution events matching the `deny` list are logged but not blocked. Use this to validate your policy before switching to `block` mode.

#### UID-based process restriction

Restrict process execution based on user ID:

```yaml
process:
  enable: true
  mode: block
  target: host
  uid:
    allow: [0, 1000]
    deny: [65534]
```

#### Combined with whitelist policy

Use the controller-generated whitelist for comprehensive process restriction:

```yaml
policy: whitelist

process:
  enable: true
  mode: block
  target: host
  allow:
    - bash
    - ls
    - cat
    - sh
    - systemctl
    - journalctl
    - dmesg
```
