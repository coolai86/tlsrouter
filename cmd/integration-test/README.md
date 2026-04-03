# ACME Shared Domain Integration Test

This test verifies the scenario where TLSrouter terminates some protocols while passthrough-ing others to a backend (e.g., Caddy), both needing certificates for the same domain.

## Architecture

```
TLSrouter A (Frontend)          TLSrouter B (Backend)
       :443                           :8443
┌─────────────────┐              ┌─────────────────┐
│  SSH terminate  │              │  HTTP terminate │
│  (CertMagic)    │              │  (CertMagic)    │
│                 │              │                 │
│  HTTP passthru ─┼──────────────► HTTP handle    │
│                 │              │                 │
│  ACME routing:  │              │  ACME handling: │
│  If active      │              │  - Own cert     │
│  challenge →    │              │                 │
│  handle here    │              └─────────────────┘
│  Else → B:8443  │
└─────────────────┘

Shared Storage (for HA):
├── challenge_tokens/
│   └── example.com.json
└── certs/
    └── example.com/
```

## Prerequisites

1. **DuckDNS Account** (free): https://www.duckdns.org/
   - Create a subdomain (e.g., `test-acme.duckdns.org`)
   - Note your token

2. **Go 1.21+**

3. **Network**: Port 443 accessible from internet (for ACME challenges)

## Environment Variables

```bash
# Required
export TEST_DOMAIN="your-subdomain.duckdns.org"
export DUCKDNS_TOKEN="your-duckdns-token"

# Optional (defaults provided)
export ACME_EMAIL="test@${TEST_DOMAIN}"
export STORAGE_DIR="/tmp/tlsrouter-acme-test"
```

## Running Tests

### Quick Test (Unit Tests)

```bash
cd /root/dev/projects/tlsrouter/worktrees/tron-tls/v2
go test -v -run TestACME
```

### Integration Test (Full ACME)

```bash
cd /root/dev/projects/tlsrouter/worktrees/tron-tls

# Set environment
export TEST_DOMAIN="test-acme.duckdns.org"
export DUCKDNS_TOKEN="your-token-here"

# Run integration test
go test -v -run TestACMESharedDomainIntegration -tags=integration ./v2/
```

### Standalone Test Runner

```bash
# Build and run
cd /root/dev/projects/tlsrouter/worktrees/tron-tls
go run ./cmd/integration-test/main.go
```

## Test Sequence

1. **TLSrouter B** starts on port 8443
   - Manages `TEST_DOMAIN` for HTTP
   - Gets certificate via Let's Encrypt Staging

2. **TLSrouter A** starts on port 443
   - Manages `TEST_DOMAIN` for SSH
   - Configures `ACMEBackends[TEST_DOMAIN] = "127.0.0.1:8443"`
   - Gets certificate via Let's Encrypt Staging

3. **Wait** for both certificates to be issued (~30 seconds)

4. **Test SSH** connection to TLSrouter A
   - Verify certificate is valid for SSH

5. **Test HTTPS** connection through TLSrouter A to B
   - Verify certificate is valid for HTTP

## Expected Behavior

### When TLSrouter A has NO active challenge:

```
Client → TLSrouter A (ACME-TLS/1 for TEST_DOMAIN)
       → HasActiveChallenge(TEST_DOMAIN) = false
       → ACMEBackends[TEST_DOMAIN] = "127.0.0.1:8443"
       → Passthrough to TLSrouter B
       → B handles ACME-TLS/1
```

### When TLSrouter A HAS active challenge:

```
Client → TLSrouter A (ACME-TLS/1 for TEST_DOMAIN)
       → HasActiveChallenge(TEST_DOMAIN) = true
       → TLSrouter A handles ACME-TLS/1
       → Connection closes cleanly after challenge
```

## Troubleshooting

### Port 443 not accessible

If you're behind NAT, you may need to:
1. Port forward 443 to your machine
2. Or use a VPS/cloud instance

### DuckDNS not updating

```bash
# Manually update DuckDNS IP
curl "https://www.duckdns.org/update?domains=${TEST_DOMAIN}&token=${DUCKDNS_TOKEN}&ip="
```

### Certificate issuance fails

1. Check Let's Encrypt Staging is working:
   ```bash
   curl -s https://acme-staging-v02.api.letsencrypt.org/directory
   ```

2. Check DNS resolution:
   ```bash
   dig ${TEST_DOMAIN}
   ```

3. Check logs:
   ```bash
   # TLSrouter logs will show ACME transaction details
   ```

### Rate Limits

Let's Encrypt Staging has very generous rate limits, but if you hit them:
- Wait 1 hour
- Use a different domain

## Files

- `v2/acme_integration_test.go` - Go test placeholders
- `cmd/integration-test/main.go` - Standalone test runner
- `v2/acme_test.go` - Unit tests for ACME logic
- `v2/certmagic_provider.go` - CertMagic wrapper with HasActiveChallenge()

## Cleaning Up

```bash
# Remove test certificates and storage
rm -rf ${STORAGE_DIR:-/tmp/tlsrouter-acme-test}

# Kill test processes
pkill -f tlsrouter
```