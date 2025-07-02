# Quick Start

## Write a configuration file

```yaml
# example.yml
network:
  mode: block
  target: host
  cidr:
    allow:
      - 0.0.0.0/0
  domain:
    deny:
      - example.com
  command:
    allow:
      - systemd-resolved
      - curl
      - safeguard
files:
  mode: block
  target: host
  allow:
    - '/'
  deny:
    - '/etc/passwd'
log:
  format: json
```

This configuration file sets the following limits:

- Block access to example.com
    - However, access allowed by specified commands with `command.allow` (such as `curl`)
- Block access to `/etc/passwd`

For more information for configurations, see [here](../configuration/network-restriction/configuration.md).

## Run

```shell
git clone --recursive git@gitee.com:openeuler/safeguard.git && cd safeguard
$ vagrant up && vagrant reload
$ vagrant ssh

$ make libbpf-static
$ make build

$ sudo ./build/safeguard --config config/safeguard.yml #|grep BLOCK
```

### Docker

```shell
$ docker run --rm -it --cgroupns=host --pid=host --privileged \
    -v /sys/kernel/:/sys/kernel/ \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /path/to/config.yaml:/config.yaml \
    --env BOUHEKI_SKIP_COMPATIBLE_CHECK=1 \
    ghcr.io/mrtc0/bouheki:latest --config /config.yaml
```