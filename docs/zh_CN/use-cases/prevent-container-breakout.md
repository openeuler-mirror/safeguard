# 防止容器逃逸

#### 阻止挂载 `/var/run/docker.sock` 到容器

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


#### 阻止容器访问 `/proc/sys` 目录

```yaml
files:
  enable: true
  mode: block
  target: container
  allow:
    - /
  deny:
    - /proc/sys
```

!!! example

    ```shell
    root@ubuntu-impish:/# ls /proc/sys
    abi  debug  dev  fs  kernel  net  user  vm

    root@ubuntu-impish:/# docker run --privileged --rm -it ubuntu:latest bash
    root@9cf961922b00:/# ls /proc/sys
    ls: cannot open directory '/proc/sys': Operation not permitted
    ```

#### 阻止特权容器逃逸

```yaml
files:
  enable: true
  mode: block
  target: container
  allow:
    - /
  deny:
    - /proc/sysrq-trigger
    - /sys/kernel
    - /proc/sys/kernel
```

!!! example

  ```shell
  root@ubuntu-impish:/# docker run --privileged --rm -it ubuntu:latest bash
  root@e3b2ffe5b284:/# echo c > /proc/sysrq-trigger
  bash: /proc/sysrq-trigger: Operation not permitted

  root@e3b2ffe5b284:/# echo '/path/to/evil' > /sys/kernel/uevent_helper
  bash: /sys/kernel/uevent_helper: Operation not permitted

  root@e3b2ffe5b284:/# echo '|/path/to/evil' > /proc/sys/kernel/core_pattern
  bash: /proc/sys/kernel/core_pattern: Operation not permitted
  ```
