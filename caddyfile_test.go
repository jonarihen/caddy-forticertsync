package forticertsync

import (
	"strings"
	"testing"

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
