package forticertsync

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile parses the Caddyfile configuration for this handler.
//
// Syntax:
//
//	forticertsync {
//	    fortigate_url <url>
//	    api_token <token>
//	    vdom <vdom_name>
//	    insecure_skip_verify
//
//	    cert <name> {
//	        domains <domain1> [domain2] ...
//	    }
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the directive name ("forticertsync")
	d.Next()

	// Parse the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "fortigate_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.FortiGateURL = d.Val()

		case "api_token":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.APIToken = d.Val()

		case "vdom":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.VDOM = d.Val()

		case "insecure_skip_verify":
			h.InsecureSkipVerify = true

		case "cert":
			if !d.NextArg() {
				return d.ArgErr()
			}
			mapping := CertMapping{
				Name: d.Val(),
			}

			// Parse optional cert sub-block
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "domains":
					mapping.Domains = d.RemainingArgs()
					if len(mapping.Domains) == 0 {
						return d.ArgErr()
					}
				default:
					return d.Errf("unrecognized option in cert block: %s", d.Val())
				}
			}

			h.Certificates = append(h.Certificates, mapping)

		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}

	return nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Handler)(nil)
