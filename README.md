# tlsrouter

A TLS Reverse Proxy for SNI and ALPN routing.

This is **v2** - a clean-room rewrite with:
- Modern Go patterns (Go 1.26+, context propagation, atomic config)
- Comprehensive test coverage (17 test suites)
- Thread-safe dynamic configuration (ready for API)
- Certmagic integration for ACME certificates
- Clean separation of concerns

## Quick Start

```sh
# Build
go build -o tlsrouter ./cmd/tlsrouter-v2

# Run with static routes (CSV)
./tlsrouter --addr :443 routes.csv

# Run with environment variables
IP_DOMAINS="vm.example.com,a.bnna.net" \
NETWORKS="192.168.1.0/24,10.0.0.0/8" \
./tlsrouter --addr :443
```

## Features

### Static Routing (CSV)

```csv
domain,alpn,backend,action
example.com,http/1.1,127.0.0.1:8080,terminate
passthrough.com,h2,127.0.0.1:443,passthrough
*.example.com,*,127.0.0.1:8081,terminate
```

### Dynamic IP Routing

URLs like `tls-192-168-1-100.vm.example.com` automatically route to `192.168.1.100`:

- `tls-` prefix: Terminate TLS, proxy to port 3080
- `tcp-` prefix: Raw passthrough to port 443

### ACME-TLS/1 Challenges

Handles three ACME scenarios:
1. **Certmagic internal**: Let's Encrypt certs via certmagic
2. **Per-domain backend**: Route challenges to specific backends
3. **Global backend**: Route all challenges to one backend

## Architecture

```
v2/
├── router.go          # Core interfaces (Router, CertProvider, Dialer)
├── handler.go         # TLS handshake with routing callback
├── server.go          # TCP server with graceful shutdown
├── config.go          # Atomic config for dynamic updates
├── cert_provider.go   # Mock and static cert providers
├── certmagic_provider.go  # Real ACME integration
└── static_router.go   # Static and dynamic routing logic
```

## Design

### Interfaces

```go
type Router interface {
    Route(sni string, alpns []string) (Decision, error)
}

type CertProvider interface {
    GetCertificate(domain string) (Certificate, error)
}
```

### Atomic Config

Thread-safe configuration swaps for dynamic API:

```go
newCfg := cfg.AddStaticRoute("example.com>http/1.1", route)
handler.SetConfig(newCfg)  // Atomic swap
```

## DNS Configuration

### CNAME (subdomains)

```text
# Terminate TLS to 3080
CNAME   site-a.example.com  tls-192-168-1-100.vm.example.net

# Raw passthrough to 443
CNAME   site-a.example.com  tcp-192-168-1-100.vm.example.net
```

### A + SRV (apex domains)

```text
A                  example.com              192.168.1.100
SRV     _http._tcp.example.com  10 3080 tls-192-168-1-100.vm.example.net
SRV      _ssh._tcp.example.com  10   22 tls-192-168-1-100.vm.example.net
```

## Port Mapping

| ALPN        | Raw Port | Decrypted Port | Notes                           |
| :---------- | -------: | -------------: | :------------------------------ |
| http/1.1    |      443 |           3080 | Non-standard to avoid conflicts |
| ssh         |   44322  |             22 | SSH over TLS needs special port  |
| h2          |      443 |              - | HTTP/2 requires passthrough     |
| acme-tls/1  |      443 |              - | ACME TLS-ALPN challenges        |
| postgresql  |     5432 |           5432 | PostgreSQL native TLS           |

See [Full Port Table](#port-mapping-table) below for all protocols.

## Development

### Prerequisites

- Go 1.26+
- certmagic v0.25.1

### Running Tests

```sh
cd v2
go test -v
# PASS: 17 test suites, 41 subtests
```

### Building

```sh
go build -o tlsrouter ./cmd/tlsrouter-v2
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IP_DOMAINS` | Comma-separated domains for dynamic routing |
| `NETWORKS` | Comma-separated CIDR networks (e.g., `192.168.1.0/24`) |
| `ACME_BACKEND` | Global ACME challenge backend |
| `ACME_BACKENDS` | Per-domain: `domain1=backend1,domain2=backend2` |

## Flags

```
  -addr string
        Address to listen on (default ":443")
  -bind string
        Address to listen on (alias for addr)
  -acme-email string
        Email for ACME registration
  -acme-dir string
        ACME directory URL (default: Let's Encrypt)
  -acme-agree
        Agree to ACME terms
```

## Roadmap

- [ ] Dynamic config API (view/add/remove routes)
- [ ] HTTP/80 redirect handler
- [ ] PROXY protocol support (v1/v2)
- [ ] Prometheus metrics endpoint
- [ ] Connection pooling for backends
- [ ] Rate limiting

## License

MPL-2.0

---

## Full Port Mapping Table

| ALPN        |    Raw Port | Decrypted Port | Comment                                                      |
| :---------- | ----------: | -------------: | :----------------------------------------------------------- |
| http/1.1    |         443 |           3080 | 3080 to be familiar, but non-default like 3000, 8080, and 80 |
| ssh         |     443*22* |             22 | sshd can't handle sclient tls directly, hence 44322 for tls  |
| ---         |         --- |            --- | _special protocols_                                          |
| acme-tls/1  |         443 |              - | for ACME / Let's Encrypt TLS SNI ALPN challenges             |
| h2          |         443 |              - | proper HTTP/2 requires raw passthrough and has no plain port |
| h2c         |           - |           3080 | plain HTTP/2, for testing/debugging                          |
| ---         |         --- |            --- | _10,000 is added to the default ports below_                 |
| coap        |        5684 |        *1*5683 | IoT, plain port is 5683                                      |
| dicom       |        2762 |        *10*104 | biomedical imaging, plain port is 104                        |
| dot         |         853 |        *100*53 | dns-over-tls, normal plain port is 53 (udp and tcp)          |
| ftp         |         990 |        *100*21 | normal plain port is 21, but it's more complicated than that |
| imap        |         993 |        *10*143 | normal plain port is 143                                     |
| irc         |        6697 |        *1*6667 | normal plain port is 6667                                    |
| managesieve |        4190 |        *1*4190 | for mail filtering, plain is also 4190                       |
| mqtt        |        8883 |        *1*1883 | normal plain port is 1883                                    |
| nntp        |         563 |        *10*119 | for News Servers, plain port is 119                          |
| ntske/1     |        4460 |        *10*123 | for NTP, normal plain port is 123                            |
| pop3        |         995 |        *10*110 | normal plain port is 110                                     |
| postgresql  |        5432 |        *1*5432 | Postgres 17+ supports direct TLS                             |
| tds/8.0     |        1433 |        *1*1433 | MS SQL 2025+ supports direct TLS                             |
| radius/1.0  |        2083 |        *1*2083 | legacy TLS optional                                          |
| radius/1.1  |        2083 |        *1*2083 | direct TLS required                                          |
| sip         |        5061 |        *1*5060 | normal plain port is 5060 (or 5080)                          |
| smb         |     *10*445 |        *10*445 | Either use requires tunneling (native SMB TLS requires QUIC) |
| webrtc      |         443 |        *100*80 | 10080 to be familiar, but not 18080, 8080, 8081, or 9000     |
| c-webrtc    |         443 |        *100*80 | "                                                            |
| xmpp-client |        5223 |        *1*5222 | client-to-server communication, default 5222 (plain)         |
| xmpp-server |        5270 |        *1*5269 | server-to-server communication, default 5269 (plain)         |

For all registered ALPNs, see <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>.

Excluded:
- `co` is UDP-only
- `doq` DNS over QUIC is UDP-only
- `http/0.9`, `http/1.0` superseded by `http/1.1`
- `h3` HTTP over QUIC is UDP-only
- `nnsp` has no port designation
- `spdy/*` superseded by `h2`
- `stun.turn` has complex implications
- `stun.nat-discovery` (same)
- `sunrpc` probably not relevant