# caddy-forticertsync

A [Caddy](https://caddyserver.com/) v2 event handler plugin that automatically syncs renewed TLS certificates into [FortiGate](https://www.fortinet.com/products/next-generation-firewall) firewalls via the FortiOS REST API.

Inspired by [nikriaz/FortiCertSync](https://github.com/nikriaz/FortiCertSync) (Windows/C#), reimplemented as a native Caddy plugin for Linux environments.

## How It Works

When Caddy obtains or renews a certificate, it emits a `cert_obtained` event. This plugin listens for that event, reads the new certificate and private key from Caddy's storage, and pushes it to your FortiGate firewall. It then rebinds any FortiGate objects (SSL-VPN, admin HTTPS, VIPs, SSL inspection profiles) that referenced the old certificate to the new one, and cleans up the old certificate.

No cron jobs, no polling, no external scripts. Just add the plugin to your Caddy build and configure it in your Caddyfile.

If FortiGate is unreachable or the API call fails, the plugin logs the error and exits cleanly &mdash; Caddy's event pipeline keeps running and the certificate renewal still succeeds.

## Requirements

- Caddy v2.11.x or newer, using the default file-system storage backend in its default data directory (the plugin reads cert/key files from `caddy.AppDataDir()`; non-default storage backends or a custom storage root are not yet supported &mdash; open an issue if you need this).
- A FortiGate running FortiOS 7.x with REST API enabled (tested against 7.6.6).

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/jonarihen/caddy-forticertsync
```

## FortiGate API User Setup

1. Go to **System > Administrators > Create New > REST API Admin**
2. Set a username (e.g., `caddy-certsync`)
3. Restrict **Trusted Hosts** to your Caddy server's IP
4. Create a custom admin profile with:
   - System > Certificates: Read/Write
   - Firewall > Policy: Read
   - VPN: Read/Write
   - System > Config: Read/Write
5. Copy the generated API token

## Caddyfile Configuration

```caddyfile
{
    events {
        on cert_obtained forticertsync {
            fortigate_url https://192.168.1.1:4443
            api_token {env.FORTIGATE_API_TOKEN}
            vdom root
            insecure_skip_verify

            cert example_com {
                domains *.example.com example.com
            }
        }
    }
}

example.com, *.example.com {
    # your normal Caddy config
}
```

### Configuration options

| Option | Required | Description |
|---|---|---|
| `fortigate_url` | yes | Base URL of the FortiGate admin interface, including port (e.g. `https://192.168.1.1:4443`). |
| `api_token` | yes | FortiGate REST API bearer token. Use `{env.VAR}` to load it from an environment variable &mdash; never paste the token literally. |
| `vdom` | no | Target VDOM name. Omit if VDOMs are disabled. |
| `insecure_skip_verify` | no | Disable TLS verification when talking to FortiGate. Common in homelabs that use a self-signed admin cert. |
| `cert <name> { domains ... }` | yes (≥1) | Maps a FortiGate certificate slot name to one or more domain identifiers. Supports exact (`example.com`) and wildcard (`*.example.com`) matching. Repeat the block for multiple certs. |

## JSON Configuration

```json
{
  "apps": {
    "events": {
      "subscriptions": [
        {
          "events": ["cert_obtained"],
          "handlers": [
            {
              "handler": "forticertsync",
              "fortigate_url": "https://192.168.1.1:4443",
              "api_token": "{env.FORTIGATE_API_TOKEN}",
              "vdom": "root",
              "insecure_skip_verify": true,
              "certificates": [
                {
                  "name": "example_com",
                  "domains": ["*.example.com", "example.com"]
                }
              ]
            }
          ]
        }
      ]
    }
  }
}
```

## Certificate Naming

Certificates are uploaded to FortiGate with a date-suffixed name to avoid in-place update issues. For example, a cert mapping with name `example_com` will be uploaded as `example_com_07052026` (format: `ddMMyyyy`). When a newer cert is synced, the old one is automatically replaced and any FortiGate objects that referenced it are rebound. The old cert is only deleted once zero references remain &mdash; rebind failures leave it in place so nothing breaks.

## Intermediate CAs

ACME `.crt` files typically contain the leaf plus one or more intermediate certificates. The plugin imports the leaf as a local certificate (under your configured cert mapping name) and each intermediate as a CA certificate named `chain_<8 hex chars>` (the first 8 hex chars of the SHA-256 of the intermediate's DER). Because the name is content-derived, the same intermediate maps to the same entry on every renewal &mdash; FortiGate's "entry already exists" response is treated as a no-op, so CA entries do not accumulate.

This matters for strict TLS clients: browsers can fetch missing intermediates via AIA, but Android (OkHttp) and Java's `TrustManager` require the server to send the full chain in the handshake. FortiGate builds that chain by looking up the leaf's issuer in its CA store, so the intermediate must be present there for the chain to be complete.

## Troubleshooting

Enable Caddy's debug logging to see detailed plugin activity:

```caddyfile
{
    debug
}
```

Common issues:
- **401 Unauthorized:** Check your API token and trusted hosts on FortiGate
- **Certificate not found:** Ensure the `cert` name matches what exists on FortiGate (check System > Certificates)
- **Connection refused:** Verify `fortigate_url` includes the correct HTTPS port
- **`failed to read certificate file`:** The plugin resolves cert/key paths against `caddy.AppDataDir()`. If you've configured a custom Caddy storage root, the resolved path won't exist &mdash; see Requirements above.
- **Android / Java clients fail with `Trust anchor for certification path not found`:** Verify with `openssl s_client -connect host:443 -showcerts < /dev/null | grep -c "BEGIN CERTIFICATE"` &mdash; you should see 2 (leaf + intermediate). If you see 1, check that a `chain_<hex>` entry exists under **System > Certificates > External CA Certificates** on the FortiGate. The plugin should create one automatically on each sync; if it's missing, look for `intermediate CA import failed` in Caddy's logs.

## Attribution

This project is a Linux/Caddy reimplementation inspired by [nikriaz/FortiCertSync](https://github.com/nikriaz/FortiCertSync), originally released under the MIT License.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE) for details.
