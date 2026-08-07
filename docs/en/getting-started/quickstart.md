# Quick Start

## Write a local quickstart configuration

```yaml
# quickstart.yaml
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

For more information for configurations, see [Network Restriction](../configuration/network-restriction/configuration.md).

## Run from Source

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

Run safeguard with the local configuration file created above:

```shell
$ sudo ./build/safeguard --config quickstart.yaml
```

Use `config/safeguard.yml` when you want to start from the repository default sample:

```shell
$ sudo ./build/safeguard --config config/safeguard.yml
```

## Verify It Works

After starting safeguard, test the file access restriction:

```shell
# This should be blocked
$ cat /etc/passwd
cat: /etc/passwd: Operation not permitted

# Check safeguard logs
$ journalctl -u safeguard -n 20
```
