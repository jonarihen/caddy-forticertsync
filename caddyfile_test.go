package forticertsync

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func parse(t *testing.T, input string) (*Handler, error) {
	t.Helper()
	d := caddyfile.NewTestDispenser(input)
	h := &Handler{}
	err := h.UnmarshalCaddyfile(d)
	return h, err
}

func TestUnmarshalCaddyfile_Full(t *testing.T) {
	input := `forticertsync {
		fortigate_url https://192.168.1.1:4443
		api_token sometoken
		vdom root
		insecure_skip_verify
		cert example_com {
			domains *.example.com example.com
		}
		cert vpn_cert {
			domains vpn.example.org
		}
	}`
	h, err := parse(t, input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.FortiGateURL != "https://192.168.1.1:4443" {
		t.Errorf("FortiGateURL = %q", h.FortiGateURL)
	}
	if h.APIToken != "sometoken" {
		t.Errorf("APIToken = %q", h.APIToken)
	}
	if h.VDOM != "root" {
		t.Errorf("VDOM = %q", h.VDOM)
	}
	if !h.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
	if len(h.Certificates) != 2 {
		t.Fatalf("Certificates len = %d, want 2", len(h.Certificates))
	}
	if h.Certificates[0].Name != "example_com" {
		t.Errorf("first cert name = %q", h.Certificates[0].Name)
	}
	if len(h.Certificates[0].Domains) != 2 {
		t.Errorf("first cert domains = %v", h.Certificates[0].Domains)
	}
}

func TestUnmarshalCaddyfile_Minimal(t *testing.T) {
	input := `forticertsync {
		fortigate_url https://fw
		api_token tok
		cert only_cert {
			domains example.com
		}
	}`
	h, err := parse(t, input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.VDOM != "" {
		t.Errorf("VDOM should be empty, got %q", h.VDOM)
	}
	if h.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should default to false")
	}
	if len(h.Certificates) != 1 || h.Certificates[0].Name != "only_cert" {
		t.Errorf("unexpected certs: %+v", h.Certificates)
	}
}

func TestUnmarshalCaddyfile_SyncAll(t *testing.T) {
	input := `forticertsync {
		fortigate_url https://fw
		api_token tok
		sync_all
	}`
	h, err := parse(t, input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !h.SyncAll {
		t.Error("SyncAll should be true")
	}
	if len(h.Certificates) != 0 {
		t.Errorf("expected zero certificate mappings, got %d", len(h.Certificates))
	}
}

func TestUnmarshalCaddyfile_Errors(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErrIn string
	}{
		{
			name: "fortigate_url missing arg",
			input: `forticertsync {
				fortigate_url
			}`,
			wantErrIn: "wrong argument count",
		},
		{
			name:      "unrecognized option",
			input:     `forticertsync { something_unknown foo }`,
			wantErrIn: "unrecognized option",
		},
		{
			name: "unrecognized option in cert block",
			input: `forticertsync {
				cert c1 {
					not_a_real_option foo
				}
			}`,
			wantErrIn: "unrecognized option in cert block",
		},
		{
			name: "cert block missing name",
			input: `forticertsync {
				cert
			}`,
			wantErrIn: "wrong argument count",
		},
		{
			name: "domains with no args",
			input: `forticertsync {
				cert c1 {
					domains
				}
			}`,
			wantErrIn: "wrong argument count",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse(t, tt.input)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrIn)
			}
			if !strings.Contains(err.Error(), tt.wantErrIn) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrIn)
			}
		})
	}
}

// ── inspection_bundle ────────────────────────────────────────────────────────
//
// The `dns` sub-directive is omitted from these cases on purpose: it resolves a
// real `dns.providers.*` Caddy module, which is only registered when the plugin
// is built into Caddy with a DNS provider. Provisioning enforces its presence
// (a bundle without DNS-01 cannot validate wildcards); parsing does not.

func TestUnmarshalCaddyfile_InspectionBundle(t *testing.T) {
	input := `forticertsync {
		fortigate_url https://172.21.12.254:443
		api_token sometoken
		sync_all
		inspection_bundle homelabrrr_inspection {
			profile inbound-deep-inspection
			email ops@example.com
			ca https://acme-staging-v02.api.letsencrypt.org/directory
			renew_before 30d
			check_interval 12h
			migrate cleanup
			supersede legacy_thing_01012026 another_legacy

			zone jackjack.dk
			zone aaris.tech {
				names extra.a.aaris.tech
			}
			zone apexonly.dk {
				wildcard off
			}
		}
	}`
	h, err := parse(t, input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b := h.Bundle
	if b == nil {
		t.Fatal("bundle not parsed")
	}
	if b.Name != "homelabrrr_inspection" {
		t.Errorf("name = %q", b.Name)
	}
	if b.Profile != "inbound-deep-inspection" {
		t.Errorf("profile = %q", b.Profile)
	}
	if b.Email != "ops@example.com" {
		t.Errorf("email = %q", b.Email)
	}
	if !strings.Contains(b.CA, "acme-staging") {
		t.Errorf("ca = %q", b.CA)
	}
	if time.Duration(b.RenewBefore) != 30*24*time.Hour {
		t.Errorf("renew_before = %v", time.Duration(b.RenewBefore))
	}
	if time.Duration(b.CheckInterval) != 12*time.Hour {
		t.Errorf("check_interval = %v", time.Duration(b.CheckInterval))
	}
	if b.Migrate != "cleanup" {
		t.Errorf("migrate = %q", b.Migrate)
	}
	if len(b.Supersede) != 2 {
		t.Errorf("supersede = %v", b.Supersede)
	}
	if len(b.Zones) != 3 {
		t.Fatalf("zones = %d, want 3", len(b.Zones))
	}
	if b.Zones[0].Domain != "jackjack.dk" || b.Zones[0].Wildcard != nil {
		t.Errorf("bare zone should default both flags: %+v", b.Zones[0])
	}
	if len(b.Zones[1].Names) != 1 || b.Zones[1].Names[0] != "extra.a.aaris.tech" {
		t.Errorf("zone names = %v", b.Zones[1].Names)
	}
	if b.Zones[2].Wildcard == nil || *b.Zones[2].Wildcard {
		t.Errorf("`wildcard off` should set the flag false: %+v", b.Zones[2])
	}

	subjects, err := b.Subjects()
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}
	// jackjack.dk x2, aaris.tech x2 + 1 extra, apexonly.dk x1
	if len(subjects) != 6 {
		t.Errorf("subjects = %v", subjects)
	}
}

func TestUnmarshalCaddyfile_BundleErrors(t *testing.T) {
	cases := map[string]string{
		"no name": `forticertsync {
			inspection_bundle {
				zone example.com
			}
		}`,
		"no zones": `forticertsync {
			inspection_bundle b { }
		}`,
		"unknown option": `forticertsync {
			inspection_bundle b {
				nonsense yes
				zone example.com
			}
		}`,
		"unknown zone option": `forticertsync {
			inspection_bundle b {
				zone example.com {
					nonsense yes
				}
			}
		}`,
		"bad duration": `forticertsync {
			inspection_bundle b {
				renew_before never
				zone example.com
			}
		}`,
		"bad on/off": `forticertsync {
			inspection_bundle b {
				zone example.com {
					wildcard maybe
				}
			}
		}`,
	}
	for name, input := range cases {
		if _, err := parse(t, input); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
}

func TestUnmarshalCaddyfile_BundleCoexistsWithMappings(t *testing.T) {
	// Zones with DNS-01 go in the bundle; everything else keeps per-domain
	// syncing and its own slot. Both must parse together.
	input := `forticertsync {
		fortigate_url https://fw
		api_token t
		cert legacy_thing {
			domains legacy.example.org
		}
		inspection_bundle homelabrrr_inspection {
			zone jackjack.dk
		}
	}`
	h, err := parse(t, input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(h.Certificates) != 1 || h.Bundle == nil {
		t.Fatalf("both mapping and bundle should survive: %d mappings, bundle=%v", len(h.Certificates), h.Bundle)
	}
	if h.Bundle.covers("legacy.example.org") {
		t.Error("an unbundled domain must not be reported as covered")
	}
}
