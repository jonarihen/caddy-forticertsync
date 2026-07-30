# caddy-forticertsync

## What this is

A Caddy v2 event handler plugin (`events.handlers.forticertsync`) that syncs renewed TLS certificates into FortiGate firewalls via the FortiOS REST API. Inspired by [nikriaz/FortiCertSync](https://github.com/nikriaz/FortiCertSync) (MIT, Windows/C#), reimplemented for Caddy/Go/Linux.

**Repository:** `github.com/jonarihen/caddy-forticertsync`
**License:** GPL v3 (GitHub-generated). Attribution to nikriaz/FortiCertSync in README.
**Build:** `xcaddy build --with github.com/jonarihen/caddy-forticertsync`

## Architecture

Caddy cert renewal -> `cert_obtained` event -> our Handler.Handle() -> reads cert+key PEM from Caddy storage -> compares with FortiGate current cert -> if newer: uploads as `<name>_<ddMMyyyy>` -> rebinds all objects referencing old cert -> deletes old cert if zero references remain.

## File structure

```
forticertsync.go       # Module registration, config structs, Handle(), matchesDomain, parsePEMCertificate
fortigate_client.go    # FortiGateClient, HTTP methods, ListCertificates, ImportCertificate, DeleteCertificate, FindCertReferences, UpdateCertReference
rebind.go              # RebindCertificates() orchestrates import -> rebind -> verify -> delete
caddyfile.go           # UnmarshalCaddyfile for Caddyfile support
README.md              # User docs (done)
LICENSE                # MIT (done, includes original nikriaz copyright)
go.mod                 # Module declaration (exists, needs go mod tidy)
```

## Current status: scaffolding is DONE

All four Go source files have working logic. The code compiles conceptually but has never had `go mod tidy` run. There are TODOs in fortigate_client.go around FortiGate date field parsing.

## Remaining work (in order)

### 1. Fix go.mod and get it compiling

Run `go mod tidy`. The go.mod currently references caddy v2.9.1; update to latest stable v2.x if needed. Verify `go build ./...` passes cleanly.

### 2. Fix TODOs in fortigate_client.go

The `ListCertificates()` function has TODOs for parsing FortiGate date fields (`valid_from`, `valid_to`). FortiGate's monitor API returns certificate dates. Research the actual field names and format from the FortiGate API. The monitor endpoint `GET /api/v2/monitor/vpn-certificate/local/select` returns results with fields like:
- `name` (string)
- `subject` (string) 
- `issuer` (string)
- `valid_from` (string, likely epoch or ISO format)
- `valid_to` (string)
- `serial_number` (string)
- `source` (string, e.g. "user" for uploaded certs)
- `q_ref` (int, reference count)
- `status` (string)

Parse these into the `FortiCert` struct properly. If the exact date format cannot be determined, use a flexible parser that handles both epoch timestamps and common date strings.

### 3. Verify FortiGate API payload format for certificate import

The `ImportCertificate()` function currently sends PEM content as raw strings. The FortiGate API endpoint `POST /api/v2/monitor/vpn-certificate/local/import` expects:
```json
{
    "type": "regular",
    "certname": "my_cert_07052026",
    "file_content": "<PEM certificate content>",
    "key_file_content": "<PEM private key content>",
    "scope": "global"
}
```

According to the Fortinet community, the PEM content should be the raw base64 body (no PEM headers, no newlines). Check if the API actually needs:
- (a) Full PEM including headers and newlines (current implementation)
- (b) Just the base64 body stripped of headers and newlines

Implement option (a) first since it's simpler. Add a comment noting option (b) may be needed if (a) fails, with a helper function `stripPEMHeaders()` ready to use.

### 4. Handle cert_obtained event data correctly

The `Handle()` function in forticertsync.go reads cert/key from disk via `os.ReadFile(certPath)`. However, Caddy's event data may provide storage keys rather than filesystem paths. The event data fields are:
- `identifier` (string) - domain name, e.g. "*.aaris.tech"
- `certificate_path` (string) - could be a storage key or filesystem path
- `private_key_path` (string) - could be a storage key or filesystem path
- `issuer_key` (string)
- `storage_path` (string)

For Caddy's default filesystem storage, these ARE filesystem paths and `os.ReadFile` works. Keep the current approach but add a comment explaining this assumption. If someone uses non-filesystem storage (e.g. consul, vault), they'd need to access Caddy's storage interface instead.

### 5. Write tests

Create these test files:

**fortigate_client_test.go:**
- Use `httptest.NewServer` to mock FortiGate API
- Test `ListCertificates()` with mock JSON response
- Test `ImportCertificate()` success and error cases
- Test `DeleteCertificate()` success and error cases
- Test `FindCertReferences()` with mock CMDB responses (singleton and list endpoints)
- Test `UpdateCertReference()` success case
- Test `GetCertificateByPattern()` matching logic (exact name, name with date suffix, no match)
- Test `buildURL()` with and without VDOM

**rebind_test.go:**
- Test full `RebindCertificates()` flow with mock server
- Test partial rebind failure (some refs fail to update, old cert not deleted)
- Test case where no references exist (should still import and succeed)
- Test case where references remain after rebind (old cert not deleted)

**caddyfile_test.go:**
- Test valid config parses correctly (all fields)
- Test minimal config (just fortigate_url, api_token, one cert)
- Test missing required fields produce errors
- Test multiple cert blocks
- Test insecure_skip_verify flag

**forticertsync_test.go:**
- Test `matchesDomain()` with exact match, wildcard match, no match, empty domains list
- Test `parsePEMCertificate()` with valid PEM, invalid PEM, empty input
- Test `Validate()` catches missing fields

### 6. Verify LICENSE

The LICENSE file is already generated by GitHub (GPL v3). Do NOT overwrite it. Just confirm it exists. The README already has the nikriaz attribution line.

### 7. Verify the full build

After all the above:
```bash
go mod tidy
go vet ./...
go build ./...
go test ./... -v
```

## FortiGate REST API reference

All calls use `Authorization: Bearer <token>`. Append `?vdom=<name>` if VDOM is enabled.

| Operation | Method | Endpoint |
|---|---|---|
| List local certs | GET | `/api/v2/monitor/vpn-certificate/local/select` |
| Import cert+key | POST | `/api/v2/monitor/vpn-certificate/local/import` |
| Delete cert | POST | `/api/v2/monitor/vpn-certificate/local/clear?mkey=<name>` |
| Get CMDB object | GET | `/api/v2/cmdb/<path>` |
| Update CMDB object | PUT | `/api/v2/cmdb/<path>[/<mkey>]` |

### CMDB endpoints that can reference certificates

| Path | Field | Type |
|---|---|---|
| `vpn.ssl/settings` | `servercert` | singleton |
| `firewall/vip` | `server-cert` | list (key: `name`) |
| `system/global` | `admin-server-cert` | singleton |
| `firewall/ssl-ssh-profile` | `server-cert` | list (key: `name`) |

## Caddyfile syntax

```caddyfile
{
    events {
        on cert_obtained forticertsync {
            fortigate_url https://192.168.1.1:4443
            api_token {env.FORTIGATE_API_TOKEN}
            vdom root                          # optional
            insecure_skip_verify               # optional flag

            cert aaris_tech {
                domains *.aaris.tech aaris.tech
            }
            cert vpn_cert {
                domains vpn.example.com
            }
        }
    }
}
```

## Inspection-bundle mode

A FortiOS SSL/SSH inspection profile caps its inbound `server-cert` list at **10
entries** (`serverCertMax` in `certname.go`). One-certificate-per-hostname syncing
exhausts that, and FortiOS won't delete a certificate a profile still references,
so the profile jams. `inspection_bundle` replaces the whole list with ONE
multi-SAN certificate the plugin orders itself.

- `bundle.go` — config structs (`InspectionBundle`, `BundleZone`), `Subjects()`,
  `covers()`, issuance via `certmagic.ACMEIssuer.Issue(ctx, csr)`, on-disk cache,
  and `state.json` (FortiGate cert base name → Caddy identifier).
- `bundle_provision.go` — builds the ACME issuer from a `dns.providers.*` Caddy
  module, starts/stops the renewal ticker.
- `bundle_reconcile.go` — `reconcile()`, the single-PUT profile swap
  (`bindProfile`), and `supersededNames()`.
- `certname.go` — `serverCertMax`, `stripDateSuffix`, `chainCAName`.

Three things here are load-bearing and must not be "simplified":

1. **The profile swap is ONE PUT.** `bindProfile` computes `[bundle] + uncovered`
   and writes it in a single request. Adding the bundle first and pruning after
   needs an 11th slot on a full profile and is rejected — that is the exact
   failure the feature exists to remove.
2. **Coverage is proven, never inferred.** `sanitizeName` maps both `.` and `-`
   to `_`, so `a-b.x.dk` (wildcard-covered) and `a.b.x.dk` (not) both become
   `a_b_x_dk`. `supersededNames` therefore only trusts `state.json`, the names it
   mints itself for a zone's apex/wildcard, and the explicit `supersede` list.
   Unproven certificates stay attached — a wasted slot beats a broken site.
3. **Bundle mode needs a timer.** Nothing else owns this certificate: it is not
   Caddy-managed, and certmagic's renewal is one-certificate-per-name
   (`Config.manageAll` iterates the name list), so it cannot drive a multi-SAN
   cert. This is the documented exception to design decision 1 below.

Wildcards require DNS-01, so every bundled zone needs credentials in the `dns`
provider. Zones without them stay on per-domain syncing and keep their own slot;
the two modes coexist. `Handle()` short-circuits any identifier `covers()`
matches, which is what makes publishing a new subdomain cost zero FortiGate work.

## Key design decisions

1. **Event-driven.** Only fires on `cert_obtained` events. No polling, no timers, no goroutines. **Exception:** inspection-bundle mode runs a renewal ticker — see above for why it has no alternative.
2. **Date-suffixed names.** New certs uploaded as `<name>_<ddMMyyyy>`. Avoids unreliable in-place updates.
3. **Safe deletion.** Old cert only deleted after confirming zero remaining references.
4. **Env var for API key.** Use `{env.FORTIGATE_API_TOKEN}` in Caddyfile. Never log the token.
5. **Insecure TLS option.** For self-signed FortiGate admin certs (common in homelabs).
6. **Graceful failure.** FortiGate sync errors are logged but don't crash Caddy. `Handle()` returns nil on non-fatal failures.
7. **No external deps.** Only Caddy v2 + Go standard library. Inspection-bundle mode uses `github.com/caddyserver/certmagic`, which is already in the tree as an indirect dependency of Caddy — no new module is added.

## Dependencies

- `github.com/caddyserver/caddy/v2` (module system, events, caddyfile, zap logger)
- `github.com/caddyserver/certmagic` (ACME issuer for inspection-bundle mode; comes in with Caddy)
- A `dns.providers.*` module (e.g. `github.com/caddy-dns/cloudflare`) must be in the xcaddy build for bundle mode — it is what solves DNS-01
- Go standard library: `crypto/x509`, `encoding/pem`, `encoding/json`, `net/http`, `crypto/tls`
