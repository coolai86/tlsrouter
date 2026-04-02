package tlsrouter

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// StaticRouter routes based on a static configuration.
type StaticRouter struct {
	// Routes maps "sni>alpn" to backend
	Routes map[string]StaticRoute
}

// StaticRoute is a single static route.
type StaticRoute struct {
	Backend    string
	Action     RouteAction
	ALPN       string
	Domain     string
}

// NewStaticRouter creates a router from a simple route map.
func NewStaticRouter(routes map[string]StaticRoute) *StaticRouter {
	return &StaticRouter{Routes: routes}
}

// Route implements Router.
func (r *StaticRouter) Route(sni string, alpns []string) (Decision, error) {
	sni = strings.ToLower(sni)

	// Check for ACME-TLS/1 challenge first - always passthrough
	for _, alpn := range alpns {
		if alpn == "acme-tls/1" {
			// Look for a wildcard or explicit route for this domain
			for _, candidate := range []string{sni + ">*", sni + ">acme-tls/1"} {
				if route, ok := r.Routes[candidate]; ok {
					return Decision{
						Action:  ActionPassthrough,
						Backend: route.Backend,
						Domain:  sni,
						ALPN:    "acme-tls/1",
					}, nil
				}
			}
			// Check wildcard subdomains
			sub := sni
			for {
				dot := strings.IndexByte(sub, '.')
				if dot == -1 {
					break
				}
				wildcard := sub[dot:]
				for _, candidate := range []string{wildcard + ">*", wildcard + ">acme-tls/1"} {
					if route, ok := r.Routes[candidate]; ok {
						return Decision{
							Action:  ActionPassthrough,
							Backend: route.Backend,
							Domain:  sni,
							ALPN:    "acme-tls/1",
						}, nil
					}
				}
				sub = sub[dot+1:]
			}
			// If no explicit route, return error - ACME requires a backend
			return Decision{}, fmt.Errorf("no route for ACME challenge on %q", sni)
		}
	}

	// Try each ALPN in order
	for _, alpn := range alpns {
		key := sni + ">" + alpn
		if route, ok := r.Routes[key]; ok {
			return Decision{
				Action:  route.Action,
				Backend: route.Backend,
				Domain:  sni,
				ALPN:    alpn,
			}, nil
		}
	}

	// Try wildcard matching
	for _, alpn := range alpns {
		// Check wildcard subdomains: ".example.com" matches "foo.example.com"
		sub := sni
		for {
			dot := strings.IndexByte(sub, '.')
			if dot == -1 {
				break
			}
			wildcard := sub[dot:] // ".example.com"
			key := wildcard + ">" + alpn
			if route, ok := r.Routes[key]; ok {
				return Decision{
					Action:  route.Action,
					Backend: route.Backend,
					Domain:  sni,
					ALPN:    alpn,
				}, nil
			}
			sub = sub[dot+1:]
		}
	}

	// Try wildcard ALPN
	for _, alpn := range alpns {
		key := sni + ">*"
		if route, ok := r.Routes[key]; ok {
			return Decision{
				Action:  route.Action,
				Backend: route.Backend,
				Domain:  sni,
				ALPN:    alpn,
			}, nil
		}
	}

	return Decision{}, fmt.Errorf("no route for %q with ALPN %v", sni, alpns)
}

// DynamicRouter routes based on IP-in-hostname patterns.
type DynamicRouter struct {
	// IPDomains are the base domains for IP routing (e.g., "vm.example.com")
	IPDomains []string

	// Networks are allowed IP networks for dynamic routing
	Networks []net.IPNet

	// PortMaps map ALPN to ports for termination and passthrough
	TerminatedPorts map[string]uint16
	RawPorts        map[string]uint16

	// ACMEPassthrough is the backend to send acme-tls/1 challenges to.
	// If empty, ACME challenges are passed through to the SNI-based backend.
	// Format: "host:port"
	ACMEPassthrough string

	// Fallback router for non-matching requests
	Fallback Router
}

// NewDynamicRouter creates a dynamic IP-based router.
func NewDynamicRouter(ipDomains []string, networks []net.IPNet) *DynamicRouter {
	return &DynamicRouter{
		IPDomains:       ipDomains,
		Networks:         networks,
		TerminatedPorts: defaultTerminatedPorts,
		RawPorts:        defaultRawPorts,
		// ACME passthrough backend - set this to route acme-tls/1 to a specific backend
		ACMEPassthrough: "",
	}
}

// Route implements Router.
func (r *DynamicRouter) Route(sni string, alpns []string) (Decision, error) {
	sni = strings.ToLower(sni)

	// Check for ACME-TLS/1 challenge - always passthrough
	for _, alpn := range alpns {
		if alpn == "acme-tls/1" {
			// If a dedicated ACME backend is configured, use it
			if r.ACMEPassthrough != "" {
				return Decision{
					Action:  ActionPassthrough,
					Backend: r.ACMEPassthrough,
					Domain:  sni,
					ALPN:    "acme-tls/1",
				}, nil
			}
			// Otherwise continue to normal routing but will force passthrough
			break
		}
	}

	// Check for IP-in-hostname pattern: tls-192-168-1-100.vm.example.com
	terminate := strings.HasPrefix(sni, "tls-")
	prefix := "tls-"
	if !terminate {
		if !strings.HasPrefix(sni, "tcp-") {
			if r.Fallback != nil {
				return r.Fallback.Route(sni, alpns)
			}
			return Decision{}, fmt.Errorf("no dynamic route for %q", sni)
		}
		terminate = false
		prefix = "tcp-"
	}

	// Extract IP from hostname
	labelEnd := strings.IndexByte(sni, '.')
	if labelEnd == -1 {
		return Decision{}, fmt.Errorf("invalid hostname format: %q", sni)
	}
	ipLabel := sni[len(prefix):labelEnd]
	sld := sni[labelEnd+1:]

	// Check domain matches
	if !slices.Contains(r.IPDomains, sld) {
		if r.Fallback != nil {
			return r.Fallback.Route(sni, alpns)
		}
		return Decision{}, fmt.Errorf("domain %q not in allowed list", sld)
	}

	// Parse IP
	ipStr := strings.ReplaceAll(ipLabel, "-", ".")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Decision{}, fmt.Errorf("invalid IP in hostname: %q", ipLabel)
	}

	// Check network allowlist
	allowed := false
	for _, network := range r.Networks {
		if network.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		return Decision{}, fmt.Errorf("IP %q not in allowed networks", ip)
	}

	// Determine port based on ALPN and terminate mode
	var port uint16
	var selectedALPN string
	portMap := r.RawPorts
	if terminate {
		portMap = r.TerminatedPorts
	}

	// First check for ACME-TLS/1 - use raw port 443
	for _, alpn := range alpns {
		if alpn == "acme-tls/1" {
			selectedALPN = "acme-tls/1"
			port = 443
			return Decision{
				Action:  ActionPassthrough,
				Backend: fmt.Sprintf("%s:%d", ipStr, port),
				Domain:  sni,
				ALPN:    selectedALPN,
			}, nil
		}
	}

	// Then check for other ALPNs
	for _, alpn := range alpns {
		if p, ok := portMap[alpn]; ok {
			selectedALPN = alpn
			port = p
			break
		}
	}

	if selectedALPN == "" {
		return Decision{}, fmt.Errorf("no supported ALPN for %q: %v", sni, alpns)
	}

	// Build backend address
	backend := fmt.Sprintf("%s:%d", ipStr, port)

	action := ActionPassthrough
	if terminate {
		action = ActionTerminate
	}

	return Decision{
		Action:  action,
		Backend: backend,
		Domain:  sni,
		ALPN:    selectedALPN,
	}, nil
}

// Default port mappings (matching original tlsrouter)
var defaultTerminatedPorts = map[string]uint16{
	"http/1.1":    3080,
	"h2c":         3080,
	"ssh":         22,
	"coap":        15683,
	"dicom":       10104,
	"dot":         10053,
	"ftp":         10021,
	"imap":        10143,
	"irc":         16667,
	"managesieve": 14190,
	"mqtt":        11883,
	"nntp":        10119,
	"ntske/1":     10123,
	"pop3":        10110,
	"postgresql":  15432,
	"tds/8.0":     11433,
	"radius/1.0":  12083,
	"radius/1.1":  12083,
	"sip":         15060,
	"smb":         10445,
	"webrtc":      10080,
	"c-webrtc":    10080,
	"xmpp-client": 15222,
	"xmpp-server": 15269,
}

var defaultRawPorts = map[string]uint16{
	"http/1.1":   443,
	"h2":         443,
	"ssh":        44322,
	"acme-tls/1": 443,
	"coap":       5684,
	"dicom":      2762,
	"dot":        853,
	"ftp":        990,
	"imap":       993,
	"irc":        6697,
	"managesieve": 4190,
	"mqtt":       8883,
	"nntp":       563,
	"ntske/1":    4460,
	"pop3":       995,
	"postgresql": 5432,
	"tds/8.0":    1433,
	"radius/1.0": 2083,
	"radius/1.1": 2083,
	"sip":        5061,
	"smb":        10445,
	"webrtc":     443,
	"c-webrtc":   443,
	"xmpp-client": 5223,
	"xmpp-server": 5270,
}

// LayeredRouter tries multiple routers in order.
type LayeredRouter struct {
	Routers []Router
}

// Route implements Router.
func (r *LayeredRouter) Route(sni string, alpns []string) (Decision, error) {
	for _, router := range r.Routers {
		decision, err := router.Route(sni, alpns)
		if err == nil {
			return decision, nil
		}
	}
	return Decision{}, fmt.Errorf("no route found for %q", sni)
}