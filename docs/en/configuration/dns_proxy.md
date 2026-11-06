# DNS Proxy

## Resolver deadlines and refresh lifecycle

The audit resolver uses one total deadline across upstreams and UDP-to-TCP retry. The default is the positive resolv.conf timeout (capped at 30 seconds), or 5 seconds; an explicit DNS client timeout takes precedence. A shorter caller deadline still wins.

- SERVFAIL and REFUSED may try the next upstream; NXDOMAIN returns immediately. NODATA is distinct from transport failures.
- Responses must match the question and opcode. Address extraction accepts only the requested owner or its response-local CNAME chain, with at most 16 hops; cycles are reported separately.
- The effective TTL is the minimum across relevant addresses and aliases. Zero is preserved in answers; zero-TTL answers are not retained in the proxy reverse cache.
- Refresh failures are exposed and retry nominally after 5, 10, 20, 40, then 60 seconds; success resets the sequence. Per-worker jitter selects 80–100% of the delay, with a one-second minimum, so successful refresh is not postponed beyond a positive TTL.
- Network audit cancellation reaches context-aware resolvers and interrupts refresh waiting. Stop/Close wait for started refresh workers before resources are released. Legacy Resolver implementations must return from their own calls; they cannot be forcibly interrupted.
- A known canceled audit rejects subsequent DNS-derived map updates before accessing BPF. Reverse-cache TTL governs log attribution; it does not by itself revoke existing BPF address entries.

The asynchronous audit resolver and the listening DNS proxy have separate lifecycles. Worker-pool limits, shared-query coalescing and a bounded stale-result policy are pending design work; they are not configuration options.

If you want to control access by [specifying domain names](./network-restriction/configuration.md), you need to select "Periodic Name Resolution" or "Change DNS Server".
Default is "Periodic Name Resolution", but recommended is "Change DNS Server".

## Periodic Name Resolution (Default)

Periodically resolves domain names and updates IP addresses in the Allow / Deny list.

!!! warning

    It is designed to perform name resolution when the TTL value reaches 0. This means that depending on the timing, there may be rare cases where communication to a restricted address is possible, or where communication to a restricted address is not possible. This often occurs in domains with short TTL, such as AWS S3.

## Change DNS Server (Recommended)

If `dns_proxy` is enabled, safeguard will start a DNS proxy on each address listed in `dns_proxy.bind`. By default, safeguard binds `127.0.0.1` and `172.17.0.1` (the default Docker bridge address).
Specify the same addresses as `nameserver` entries in `/etc/resolv.conf`.
If the domain to be name resolved is restricted, update the IP address in the Allow / Deny list.

!!! warning

    If you are using systemd-resolved, change `/etc/systemd/resolved.conf` instead of `/etc/resolv.conf`.
    For example:

    ```
    DNS=127.0.0.1 172.17.0.1
    ```

## Proxy operation and troubleshooting

- Requests must contain one IN-class question. The proxy forwards queries to configured upstreams, retrying on SERVFAIL, REFUSED or transport errors (including a failed TCP retry); NXDOMAIN is returned directly. UDP truncation triggers one TCP retry to that upstream.
- Proxy upstream attempts use the client timeout per exchange; they do not share the audit resolver's total deadline. A response write failure is logged.
- Only relevant A/AAAA records from the question's response-local CNAME chain update the cache and policy. Reverse-cache addresses expire by TTL and are limited to 4096 IPs and 16 names per IP.
- Duplicate listeners, an IPv4 wildcard combined with a specific IPv4 listener, and statically identifiable upstream loops are rejected at configuration load. Hostnames are not resolved during this check.
- Use `safeguard controller validate --config <path>` to check the configuration without loading BPF. Check proxy logs for upstream and response-write errors.

## Current configuration options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable DNS Proxy or not. Default is `false`. |
| `upstreams` | List | List of upstream DNS servers. Required when `enable` is `true`. |
| `bind` | List | Local addresses where the DNS proxy listens. Default is `127.0.0.1` and `172.17.0.1`. |

```yaml
network:
  enable: true
dns_proxy:
  enable: true
  upstreams:
    - 8.8.8.8
    - 8.8.4.4
  bind:
    - 127.0.0.1
    - 172.17.0.1
```
