package forticertsync

import (
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
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

		case "sync_all":
			h.SyncAll = true

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

		case "inspection_bundle":
			bundle, err := parseInspectionBundle(d)
			if err != nil {
				return err
			}
			h.Bundle = bundle

		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}

	return nil
}

// parseInspectionBundle parses the inspection_bundle block:
//
//	inspection_bundle <name> {
//	    profile        <ssl-ssh-profile>
//	    dns            <provider> [args...]
//	    email          <address>
//	    ca             <acme_directory_url>
//	    renew_before   <duration>
//	    check_interval <duration>
//	    migrate        off|cleanup
//	    supersede      <cert_base_name>...
//
//	    zone <domain> {
//	        wildcard   off        # default on
//	        apex       off        # default on
//	        names      <extra hostnames>...
//	    }
//	}
func parseInspectionBundle(d *caddyfile.Dispenser) (*InspectionBundle, error) {
	b := &InspectionBundle{}
	if d.NextArg() {
		b.Name = d.Val()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "name":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			b.Name = d.Val()

		case "profile":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			b.Profile = d.Val()

		case "email":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			b.Email = d.Val()

		case "ca":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			b.CA = d.Val()

		case "migrate":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			b.Migrate = strings.ToLower(d.Val())

		case "supersede":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			b.Supersede = append(b.Supersede, args...)

		case "renew_before", "check_interval":
			key := d.Val()
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("parsing %s: %v", key, err)
			}
			if key == "renew_before" {
				b.RenewBefore = caddy.Duration(dur)
			} else {
				b.CheckInterval = caddy.Duration(dur)
			}

		case "dns":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			provName := d.Val()
			// Same shape as a `tls { dns ... }` block: hand the remaining
			// tokens to the dns.providers.* module so existing provider
			// config (e.g. `dns cloudflare {env.CF_API_TOKEN}`) works here.
			unm, err := caddyfile.UnmarshalModule(d, "dns.providers."+provName)
			if err != nil {
				return nil, err
			}
			b.DNSRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)

		case "zone":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			zone := BundleZone{Domain: strings.ToLower(d.Val())}
			for zn := d.Nesting(); d.NextBlock(zn); {
				switch d.Val() {
				case "wildcard":
					on, err := parseOnOff(d, true)
					if err != nil {
						return nil, err
					}
					zone.Wildcard = &on
				case "apex":
					on, err := parseOnOff(d, true)
					if err != nil {
						return nil, err
					}
					zone.Apex = &on
				case "names":
					args := d.RemainingArgs()
					if len(args) == 0 {
						return nil, d.ArgErr()
					}
					zone.Names = append(zone.Names, args...)
				default:
					return nil, d.Errf("unrecognized option in zone block: %s", d.Val())
				}
			}
			b.Zones = append(b.Zones, zone)

		default:
			return nil, d.Errf("unrecognized option in inspection_bundle block: %s", d.Val())
		}
	}

	if b.Name == "" {
		return nil, d.Err("inspection_bundle requires a name")
	}
	if len(b.Zones) == 0 {
		return nil, d.Err("inspection_bundle requires at least one zone")
	}
	return b, nil
}

// parseOnOff reads a bare flag (meaning def) or an explicit on/off argument.
func parseOnOff(d *caddyfile.Dispenser, def bool) (bool, error) {
	if !d.NextArg() {
		return def, nil
	}
	switch strings.ToLower(d.Val()) {
	case "on", "true", "yes":
		return true, nil
	case "off", "false", "no":
		return false, nil
	default:
		return false, d.Errf("expected on/off, got %q", d.Val())
	}
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Handler)(nil)
