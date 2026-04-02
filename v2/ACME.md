# ACME-TLS/1 Challenge Handling

## Problem

When you're running a TLS reverse proxy behind another TLS terminator, you face a chicken-and-egg problem:

1. To get a valid certificate via ACME (Let's Encrypt), you need to prove domain ownership
2. The ACME-TLS/1 challenge requires raw TLS passthrough to your backend
3. But your proxy needs valid certificates to terminate TLS in the first place

## Solution

The router treats `acme-tls/1` as a **special-case ALPN** that always forces passthrough, regardless of other routing configuration.

## Flow

### For Static Routes

```go
// Wildcard route that catches all protocols including ACME
"example.com>*": {
    Backend: "192.168.1.100:443",
    Action:  ActionTerminate, // This is ignored for ACME
}

// Or explicit ACME route
"example.com>acme-tls/1": {
    Backend: "192.168.1.100:443",
    Action:  ActionTerminate, // This is ignored for ACME
}
```

When a client sends `acme-tls/1` in its ALPN list:

1. StaticRouter checks for ACME first (before normal routing)
2. Finds matching route (wildcard or explicit)
3. Returns `ActionPassthrough` with backend address
4. Handler tunnels raw TLS to backend

### For Dynamic Routes (IP-in-hostname)

```go
// Dynamic routing config
IPDomains:  []string{"vm.example.com"}
Networks:   []net.IPNet{*net.ParseCIDR("192.168.1.0/24")}
```

When a client connects to `tls-192-168-1-100.vm.example.com` with `acme-tls/1`:

1. DynamicRouter detects `acme-tls/1` in ALPN list
2. Ignores the `tls-` prefix (normally means terminate)
3. Uses port 443 (raw TLS passthrough)
4. Returns `ActionPassthrough` to `192.168.1.100:443`

### Dedicated ACME Backend (Optional)

```go
router := NewDynamicRouter(ipDomains, networks)
router.ACMEPassthrough = "10.0.0.1:443" // Dedicated ACME challenge server
```

When configured, ALL `acme-tls/1` challenges route to the dedicated backend, regardless of SNI.

## Handler Behavior

```go
// In handler.go
GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
    // Router makes decision
    decision, err := h.Router.Route(hello.ServerName, hello.SupportedProtos)

    // If passthrough (including ACME)
    if decision.Action == ActionPassthrough {
        return nil, ErrPassthrough  // Special error signals passthrough
    }

    // Otherwise terminate normally
    // ...
}
```

After `Handshake()`:

```go
err := tlsConn.Handshake()
if err == ErrPassthrough {
    // Tunnel the peeked TLS bytes + rest of connection to backend
    return h.tunnelTCP(tracking, decision.Backend)
}
```

## Example: Getting Certs Behind Another Proxy

### Setup

1. Frontend proxy (public): `proxy.example.com`
2. Your backend server: `10.11.8.202:443`
3. Dynamic DNS: `tcp-10-11-8-202.vm.example.com` → points to proxy

### Configuration

On your backend (where `tlsrouter` runs):

```env
IP_DOMAINS=a.bnna.net
NETWORKS=10.11.8.0/24
```

### Process

1. Point DNS for `yourdomain.com` to `proxy.example.com`
2. Configure frontend proxy to passthrough `tcp-10-11-8-202.a.bnna.net` → `10.11.8.202:443`
3. Run certbot on backend using `tcp-10-11-8-202.a.bnna.net` as the SNI
4. ACME-TLS/1 challenge goes: Client → Frontend → Backend (via tcp URL)
5. Backend router detects `acme-tls/1`, tunnels raw TLS to local `10.11.8.202:443`
6. Certbot on `10.11.8.202:443` handles challenge
7. Certificate obtained!
8. Now you can terminate TLS for `yourdomain.com`

### Certbot Command

```bash
certbot certonly --manual \
  --preferred-challenges tls-alpn-01 \
  --manual-public-ip-logging-ok \
  -d tcp-10-11-8-202.a.bnna.net
```

This requests a certificate for the dynamic hostname, which tunnels through to your backend.

## Testing

```bash
# Test ACME challenge passthrough
openssl s_client -connect example.com:443 \
  -servername example.com \
  -alpn acme-tls/1 \
  -showcerts

# Should see raw backend response (not terminated by proxy)
```

## Security Notes

- ACME challenges are always passthrough, never terminated
- This is intentional - ACME requires the original TLS ClientHello
- The backend handling ACME must be configured to respond to ACME-TLS/1
- Certmagic/Caddy handles this automatically when configured for ACME
- Only allow ACME for domains you actually control (DNS records required)