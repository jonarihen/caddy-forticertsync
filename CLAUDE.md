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

## Key design decisions

1. **Event-driven.** Only fires on `cert_obtained` events. No polling, no timers, no goroutines.
2. **Date-suffixed names.** New certs uploaded as `<name>_<ddMMyyyy>`. Avoids unreliable in-place updates.
3. **Safe deletion.** Old cert only deleted after confirming zero remaining references.
4. **Env var for API key.** Use `{env.FORTIGATE_API_TOKEN}` in Caddyfile. Never log the token.
5. **Insecure TLS option.** For self-signed FortiGate admin certs (common in homelabs).
6. **Graceful failure.** FortiGate sync errors are logged but don't crash Caddy. `Handle()` returns nil on non-fatal failures.
7. **No external deps.** Only Caddy v2 + Go standard library.

## Dependencies

- `github.com/caddyserver/caddy/v2` (module system, events, caddyfile, zap logger)
- Go standard library: `crypto/x509`, `encoding/pem`, `encoding/json`, `net/http`, `crypto/tls`
