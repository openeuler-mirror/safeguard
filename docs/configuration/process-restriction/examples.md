#### Monitor process execution

```yaml
process:
  enable: true
  mode: monitor
  target: host
```

!!! example

    ```shell
    safeguard logs process execution events without blocking them.
    ```

#### Allow only selected process names

```yaml
policy: whitelist
process:
  enable: true
  mode: block
  target: host
  allow:
    - bash
    - sh
    - python3
```

!!! example

    ```shell
    # /usr/bin/curl https://example.com
    bash: /usr/bin/curl: Operation not permitted
    ```
