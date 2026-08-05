#### Block mount `/var/run/docker.sock` to container

The `deny` list contains mount source paths or device names.

```yaml
mount:
  enable: true
  mode: block
  target: host
  deny:
    - /var/run/docker.sock
```

!!! example

    ```shell
    # docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu:latest bash
    docker: Error response from daemon: OCI runtime create failed: container_linux.go:380: starting container process caused: process_linux.go:545: container init caused: rootfs_linux.go:76: mounting "/var/run/docker.sock" to rootfs at "/var/run/docker.sock" caused: mount through procfd: operation not permitted: unknown.
    ```

#### Block mount of sensitive filesystems

Prevent mounting of sensitive kernel filesystems like `/proc` and `/sys`:

```yaml
mount:
  enable: true
  mode: block
  target: container
  deny:
    - /proc
    - /sys
```

#### Block mount of host root filesystem

Prevent mounting the host root filesystem into containers:

```yaml
mount:
  enable: true
  mode: block
  target: host
  deny:
    - /
```

#### Monitor mode for testing

Use monitor mode to observe mount events before blocking:

```yaml
mount:
  enable: true
  mode: monitor
  target: host
  deny:
    - /var/run/docker.sock
    - /dev
```

!!! note

    In monitor mode, all mount events matching the `deny` list are logged but not blocked. Use this to validate your policy before switching to `block` mode.
