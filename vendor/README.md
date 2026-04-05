# Vendored Frontend Assets

This directory contains vendored frontend dependencies for the TLSrouter dashboard.

## Structure

```
vendor/
├── datastar/
│   ├── datastar.js      # Datastar v1.0.0-RC.7
│   ├── download.sh      # POSIX shell download script
│   └── download.ps1     # PowerShell download script
└── oat/
    ├── oat.min.css      # Oat.ink CSS (~31KB)
    ├── oat.min.js       # Oat.ink JS (~6KB)
    ├── download.sh      # POSIX shell download script
    └── download.ps1     # PowerShell download script
```

## Updating Dependencies

### Datastar

```bash
# POSIX (Linux/macOS)
cd vendor/datastar
./download.sh v1.0.0-RC.7

# PowerShell (Windows)
cd vendor/datastar
.\download.ps1 -Version v1.0.0-RC.7
```

### Oat.ink

```bash
# POSIX (Linux/macOS)
cd vendor/oat
./download.sh

# PowerShell (Windows)
cd vendor\oat
.\download.ps1
```

## v2/ Module Copy

The `v2/vendor/` directory contains copies of these assets for `go:embed`:

```bash
# After updating vendor/*, sync to v2/vendor/
cp vendor/datastar/datastar.js v2/vendor/
cp vendor/oat/oat.min.css v2/vendor/
cp vendor/oat/oat.min.js v2/vendor/
```

## Why Vendor?

- **Zero runtime dependencies** — no CDN calls, works offline
- **Stable versions** — pinned versions, no surprise breakage
- **Reproducible builds** — same binary from same commit
- **Self-contained** — single binary serves everything

## Licenses

- **Datastar** — MIT License (https://github.com/starfederation/datastar)
- **Oat.ink** — MIT License (https://oat.ink)