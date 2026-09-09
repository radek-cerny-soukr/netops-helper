# Configuration

## Local proxy

The proxy uses these environment variables:

| Variable | Default |
| --- | --- |
| `NETOPS_VAULT_PATH` | `$XDG_CONFIG_HOME/netops-helper/vault.json` |
| `NETOPS_KNOWN_HOSTS_PATH` | `~/.ssh/known_hosts` |
| `NETOPS_TARGET_POLICY_PATH` | `$XDG_CONFIG_HOME/netops-helper/target-policy.json` |
| `NETOPS_MASTER_ALIAS` | `netops-runner` |

The credential file is one valid JSON object with one target record per line. Each record contains exactly `host`, `port`, `login`, and `password`; set mode `600`. The proxy parses the standard JSON object and injects only the selected record. Compact and pretty-printed JSON are both accepted. Do not use JSONL and never place credentials in the project directory, command line, logs, or source control.

Password-backed records are currently supported for portability. They are a residual risk, not the preferred production design. Use a dedicated secret broker or platform-appropriate key/certificate integration in a hardened deployment.

## Target policy

`target-policy.json` is non-secret but security-sensitive. Every target requires explicit read-only enrollment:

```json
{
  "device-alias": {
    "account_role": "read-only",
    "fortios_output_standard_verified": false,
    "read_inventory": {
      "interfaces": ["example-interface"],
      "services": ["example.service"],
      "addresses": ["192.0.2.10"]
    },
    "https_endpoints": [
      {"path": "/api/v2/monitor/system/status", "port": 443, "use_basic_auth": false}
    ],
    "sftp_roots": ["/srv/netops"],
    "rate_limit": {"requests": 12, "window_seconds": 60}
  }
}
```

The `account_role` value records an operator assertion. It causes missing enrollment to fail closed, but cannot prove remote authorization. Verify the actual account independently as described in [Read-only accounts](read-only-accounts.md).

Typed SSH slots must exactly match the corresponding inventory category. Values are also type-checked and control characters are rejected. Keep inventories narrow and review them after topology changes. Device output can never enroll a value.

`https_endpoints` is an exact per-target allowlist of path (including any query string), port, and Basic-auth choice. An empty list denies `https_get`; the caller cannot introduce a path or port, or attach credentials where policy forbids them. Review every allowlisted GET endpoint for mutation semantics before enrollment.

SFTP roots must be absolute, non-root paths without `..`. Both SFTP reads and FTP/FTPS listings must equal a configured root or be its descendant. Missing or invalid configuration denies access. Remote permissions or chroot remain necessary because lexical checks do not resolve remote symlinks.

The proxy enforces a per-target sliding-window request limit in each proxy process before credential injection. The default is 12 device calls per 60 seconds; `requests` is bounded to 1-60 and `window_seconds` to 1-3600. Choose a lower limit where authentication lockout or device load is sensitive.

For FortiOS, set `fortios_output_standard_verified` to `true` only after independently configuring and verifying `set output standard` as described in [Read-only accounts](read-only-accounts.md). Other platforms leave it `false`.

## Trust and FTPS pins

OpenSSH host keys must be pre-enrolled and are checked strictly. Never use `StrictHostKeyChecking=no` or automatic host-key acceptance.

The public container uses the base-image CA bundle. Private HTTPS CAs require a reviewed derived image. FTPS pins use `/etc/netops-helper/tls-pins.json` and certificates under `/etc/netops-helper/certs`; the public defaults contain no private trust material.

## Container state

Only `/var/lib/netops-helper` is persistent. It contains secret-free audit segments. The active segment and four retained segments are each limited to 2,000,000 bytes. Temporary host-key files live in tmpfs.
