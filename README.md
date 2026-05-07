# caddy-forticertsync

A [Caddy](https://caddyserver.com/) v2 event handler plugin that automatically syncs renewed TLS certificates into [FortiGate](https://www.fortinet.com/products/next-generation-firewall) firewalls via the FortiOS REST API.

Inspired by [nikriaz/FortiCertSync](https://github.com/nikriaz/FortiCertSync) (Windows/C#), reimplemented as a native Caddy plugin for Linux environments.

## How It Works

When Caddy obtains or renews a certificate, it emits a `cert_obtained` event. This plugin listens for that event, reads the new certificate and private key from Caddy's storage, and pushes it to your FortiGate firewall. It then rebinds any FortiGate objects (SSL-VPN, admin HTTPS, VIPs, SSL inspection profiles) that referenced the old certificate to the new one, and cleans up the old certificate.

No cron jobs, no polling, no external scripts. Just add the plugin to your Caddy build and configure it in your Caddyfile.

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

            cert aaris_tech {
                domains *.aaris.tech aaris.tech
            }
        }
    }
}

aaris.tech, *.aaris.tech {
    # your normal Caddy config
}
```

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
                  "name": "aaris_tech",
                  "domains": ["*.aaris.tech", "aaris.tech"]
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

Certificates are uploaded to FortiGate with a date-suffixed name to avoid in-place update issues. For example, a cert mapping with name `aaris_tech` will be uploaded as `aaris_tech_07052026` (format: `ddMMyyyy`). When a newer cert is synced, the old one is automatically replaced and cleaned up.

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

## Attribution

This project is a Linux/Caddy reimplementation inspired by [nikriaz/FortiCertSync](https://github.com/nikriaz/FortiCertSync), originally released under the MIT License.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE) for details.
