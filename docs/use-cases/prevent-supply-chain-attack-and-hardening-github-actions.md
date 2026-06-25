# Prevent Supply Chain Attacks and Hardening GitHub Actions Self-hosted Runner

In recent years, there have been many incidents of credentials being compromised from CI / CD environments due to supply chain attacks.  
Signature verification and hash verification help prevent supply chain attacks, and egress restriction is another measure that should be taken.
safeguard can be installed in a CI/CD environment to restrict network communication by domain name or process name.

## Hardening GitHub Actions Self-hosted Runner

Hardening a Workflow running on GitHub Actions Self-hosted Runner is done in the following steps:

### 1. Install safeguard

Install safeguard with reference to [Installation](../getting-started/installation.md).

### 2. Create the safeguard configuration file

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    # Add DNS servers and internal networks used by the runner.
    allow: ["8.8.8.8/32", "8.8.4.4/32", "127.0.0.1/32", "10.0.0.8/32", "172.16.0.0/12", "192.168.0.0/16"]
  domain:
    allow:
      # https://docs.github.com/ja/actions/hosting-your-own-runners/about-self-hosted-runners#
      - "github.com"
      - "api.github.com"
      - "codeload.github.com"
      - "objects.github.com"
      - "objects.githubusercontent.com"
      - "objects-origin.githubusercontent.com"
      - "github-releases.githubusercontent.com"
      - "github-registry-files.githubusercontent.com"
dns_proxy:
  enable: true
  # Upstream DNS servers queried by the proxy.
  upstreams:
    - 8.8.8.8
    - 8.8.4.4
  # Listen on localhost and Docker's default bridge address.
  bind:
    - 127.0.0.1
    - 172.17.0.1
log:
  format: json
```

### 3. Change the DNS Server to be used

Point `/etc/resolv.conf` to the addresses configured in `dns_proxy.bind`.
The proxy forwards requests to `dns_proxy.upstreams`. Include `172.17.0.1`, Docker's default bridge address, so containers can resolve names through the proxy.

```shell
$ cat /etc/resolv.conf
nameserver 127.0.0.1
nameserver 172.17.0.1
search .
```

If you are using systemd-resolved, do not modify `/etc/resolv.conf`. Set `DNS` in `/etc/systemd/resolved.conf` to the same `dns_proxy.bind` addresses.

```shell
# cat /etc/systemd/resolved.conf
[Resolve]
DNS=127.0.0.1 172.17.0.1

# systemctl restart systemd-resolved
```
