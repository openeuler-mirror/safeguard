#### Monitor process create

```yaml
mount:
  mode: monitor
  target: host
```

!!! example

    ```shell
    # docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu:latest bash
    docker: Error response from daemon: OCI runtime create failed: container_linux.go:380: starting container process caused: process_linux.go:545: container init caused: rootfs_linux.go:76: mounting "/var/run/docker.sock" to rootfs at "/var/run/docker.sock" caused: mount through procfd: operation not permitted: unknown.
    ```