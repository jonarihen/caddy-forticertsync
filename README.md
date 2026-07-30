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

### Sync-everything mode

If you'd rather have every certificate Caddy issues land on the FortiGate without listing them one by one, set `sync_all` and drop the `cert` blocks:

```caddyfile
{
    events {
        on cert_obtained forticertsync {
            fortigate_url https://192.168.1.1:4443
            api_token {env.FORTIGATE_API_TOKEN}
            sync_all
        }
    }
}
```

Each identifier gets a FortiGate cert slot named `sanitizeName(identifier)` (e.g. `*.example.com` &rarr; `wildcard_example_com`). You can still add `cert` blocks alongside `sync_all` to override the auto-derived name for specific identifiers; explicit mappings always win.

### Inspection-bundle mode (recommended once you pass ~8 sites)

A FortiOS SSL/SSH inspection profile holds **at most 10 entries** in its inbound
`server-cert` list. Mirroring one Caddy certificate per hostname burns a slot per
site, so the profile fills up and publishing further sites fails with:

```
Too many server certificate entries. Maximum number of entries: 10;
attribute set operator error, -4, discard the setting
```

It is worse than it looks, because FortiOS refuses to delete a certificate that a
profile still references &mdash; so the superseded ones cannot be cleared either.

Inspection-bundle mode replaces that with **one** certificate whose SAN list
covers every name the FortiGate needs to inspect. Caddy keeps issuing and serving
its own per-site certificates exactly as before; the bundle exists only to be
presented by the FortiGate, which selects it for every SNI in its SAN list.

```caddyfile
{
    events {
        on cert_obtained forticertsync {
            fortigate_url https://192.168.1.1:4443
            api_token {env.FORTIGATE_API_TOKEN}
            insecure_skip_verify
            sync_all

            inspection_bundle homelabrrr_inspection {
                profile inbound-deep-inspection
                email you@example.com
                dns cloudflare {env.CF_API_TOKEN}

                zone example.com          # -> example.com + *.example.com
                zone example.org
                zone another.dev
            }
        }
    }
}
```

Each `zone` contributes the apex **and** the wildcard, because a wildcard does not
cover its own apex. Six zones is 12 identifiers in one certificate, well inside
Let's Encrypt's 100-identifier limit &mdash; and it occupies **one** profile slot
instead of twelve. Publishing a new subdomain under a bundled zone then costs
nothing at all: it is already inside `*.example.com`, so the plugin skips the
FortiGate entirely.

> **Wildcards require DNS-01 validation.** Every bundled zone needs credentials
> in the configured `dns` provider. Zones you cannot validate over DNS-01 must be
> left out of the bundle &mdash; they keep per-domain syncing and their own slot.
> Both modes run side by side.

**Test against staging first.** A bundle covering many zones is exactly the kind
of order you do not want to burn production rate limits on:

```caddyfile
ca https://acme-staging-v02.api.letsencrypt.org/directory
```

#### Migrating an existing deployment

Point `profile` at the profile that is already full and start Caddy. On the first
reconcile the plugin issues the bundle, imports it, and then rewrites the
profile's certificate list **in a single PUT**: the bundle plus every entry it
does *not* cover. Doing it in one write is what makes migration possible at the
cap &mdash; adding the bundle first and pruning afterwards would need an 11th slot
and be rejected.

Superseded certificates are then deleted, but only the ones whose coverage can be
*proven*, and only once the FortiGate confirms nothing else references them.
Coverage is proven from the plugin's own record of which identifier each name was
synced for (`state.json` in the data dir), plus the names it would itself mint for
a zone's apex and wildcard. Anything unproven is left attached and logged &mdash;
that costs a slot, but it can never break a live site.

Why not just derive the identifier from the name? Because `sanitizeName` maps both
`.` and `-` to `_`, so `a-b.example.com` (covered by `*.example.com`) and
`a.b.example.com` (**not** covered) both arrive as `a_b_example_com`. Guessing
wrong would delete a certificate a live site depends on. Use `supersede` to name
such certificates explicitly once you have checked them:

```caddyfile
supersede old_thing another_old_thing
```

Set `migrate off` to attach the bundle without deleting anything.

#### Renewal

Bundle mode starts a background timer (default every 12h; `check_interval`). This
is the one place the plugin's otherwise strictly event-driven design does not
apply, and deliberately so: nothing else owns the bundle. It is not one of Caddy's
managed certificates, and certmagic's own renewal machinery is strictly
one-certificate-per-name, so it cannot drive a multi-SAN certificate. Hanging
renewal off unrelated `cert_obtained` events would make it depend on some other
certificate happening to renew in time &mdash; correct only by coincidence.

Each check is cheap and makes no network calls unless the cached certificate is
missing, within `renew_before` (default 30d) of expiry, or its SAN set no longer
matches the configured zones. Adding or removing a `zone` therefore re-issues the
bundle on the next check.

#### Bundle options

| Option | Required | Description |
|---|---|---|
| `inspection_bundle <name>` | &mdash; | Enables bundle mode. `<name>` is the FortiGate certificate base name; the live object is `<name>_<ddMMyyyy>`. |
| `dns <provider> [...]` | yes | DNS provider module for DNS-01, same syntax as a `tls { dns ... }` block. Required &mdash; wildcards cannot be validated any other way. |
| `zone <domain> { ... }` | yes (≥1) | A parent domain. Adds `<domain>` and `*.<domain>` by default; `wildcard off` / `apex off` drop either, and `names <host>...` adds extras (needed for depth-2 names like `a.b.example.com`). |
| `profile <name>` | no | SSL/SSH inspection profile to bind the bundle to. Omit to import and rebind existing references without binding a new profile. |
| `email <address>` | no | ACME account contact. |
| `ca <url>` | no | ACME directory URL. Defaults to Let's Encrypt production. |
| `renew_before <duration>` | no | Remaining validity that triggers renewal. Default `30d`. |
| `check_interval <duration>` | no | How often expiry is re-checked. Default `12h`. |
| `migrate off\|cleanup` | no | `cleanup` (default) removes superseded certificates after the swap; `off` leaves them in place. |
| `supersede <name>...` | no | Extra certificate base names to treat as covered during migration. |

### Configuration options

| Option | Required | Description |
|---|---|---|
| `fortigate_url` | yes | Base URL of the FortiGate admin interface, including port (e.g. `https://192.168.1.1:4443`). |
| `api_token` | yes | FortiGate REST API bearer token. Use `{env.VAR}` to load it from an environment variable &mdash; never paste the token literally. |
| `vdom` | no | Target VDOM name. Omit if VDOMs are disabled. |
| `insecure_skip_verify` | no | Disable TLS verification when talking to FortiGate. Common in homelabs that use a self-signed admin cert. |
| `sync_all` | no | Sync every renewed certificate to FortiGate, even ones not covered by an explicit `cert` block. Auto-derived names follow `sanitizeName(identifier)` (lowercase, dots/dashes &rarr; underscores, `*.` &rarr; `wildcard_`). Explicit `cert` blocks still take precedence. When set, the `cert` block is optional. Identifiers covered by an `inspection_bundle` are skipped. |
| `cert <name> { domains ... }` | yes (≥1 unless `sync_all` or `inspection_bundle`) | Maps a FortiGate certificate slot name to one or more domain identifiers. Supports exact (`example.com`) and wildcard (`*.example.com`) matching. Repeat the block for multiple certs. |
| `inspection_bundle <name> { ... }` | no | One multi-SAN certificate for the whole FortiGate instead of one per hostname. See [Inspection-bundle mode](#inspection-bundle-mode-recommended-once-you-pass-8-sites). |

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
