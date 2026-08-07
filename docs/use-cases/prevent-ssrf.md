# Prevent SSRF Attacks

Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can cause the server to make requests to unintended destinations. In cloud environments, the metadata service (169.254.169.254) is a common SSRF target that can expose instance credentials.

## Block Cloud Metadata Service

Block access to the public cloud Metadata Service. This is a mitigation measure against SSRF attacks targeting cloud instance metadata.

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

## Block Internal Network Access

For workloads that should only access the public internet, block internal network ranges:

```yaml
network:
  enable: true
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 169.254.169.254/32
```

## Container-Only SSRF Protection

Apply SSRF protection only to containers:

```yaml
network:
  enable: true
  mode: block
  target: container
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

## Monitoring First

Use monitor mode to validate before blocking:

```yaml
network:
  enable: true
  mode: monitor
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

Review the logs to confirm the policy works as expected, then switch to `block` mode.

## Combined with Domain Filtering

Block SSRF via domain names using DNS proxy:

```yaml
network:
  enable: true
  mode: block
  target: host
  domain:
    deny:
      - metadata.google.internal
      - metadata.azure.com

dnsproxy:
  enable: true
  listen: "127.0.0.1:53"
  upstream:
    - 8.8.8.8
```
