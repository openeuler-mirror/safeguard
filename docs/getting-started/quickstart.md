# Quick Start

## Write a configuration file

```yaml
# example.yml
network:
  enable: true
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
  enable: true
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
- Allow access from commands listed in `command.allow`, such as `curl`
- Block access to `/etc/passwd`

For more information for configurations, see [here](../configuration/network-restriction/configuration.md).

## Run from source

Clone the repository and enter the development environment:

```shell
$ git clone --recursive https://atomgit.com/openeuler/safeguard.git && cd safeguard
$ vagrant up && vagrant reload
$ vagrant ssh
```

Build safeguard inside the environment:

```shell
$ make libbpf-static
$ make build
```

Run safeguard with the configuration file created above:

```shell
$ sudo ./build/safeguard --config example.yml
```

Use the packaged sample config when you want to start from the repository defaults:

```shell
$ sudo ./build/safeguard --config config/safeguard.yml
```
