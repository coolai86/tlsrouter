# Vendored Frontend Assets

This directory contains vendored frontend dependencies for the TLSrouter dashboard.

## Structure

```
frontend/
├── README.md
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

## Why `frontend/` instead of `vendor/`?

Go reserves `./vendor/` for Go module dependencies. Frontend assets must go in a different directory to avoid conflicts with `go mod vendor`.

## Embedding

The `v2/frontend/` directory contains copies for `go:embed`:

```go
//go:embed frontend/datastar.js
//go:embed frontend/oat.min.css
//go:embed frontend/oat.min.js
var frontendAssets embed.FS
```

## Updating Dependencies

### Datastar

```bash
# POSIX (Linux/macOS)
cd frontend/datastar && ./download.sh v1.0.0-RC.7

# PowerShell (Windows)
cd frontend\datastar
.\download.ps1 -Version v1.0.0-RC.7
```

### Oat.ink

```bash
# POSIX (Linux/macOS)
cd frontend/oat && ./download.sh

# PowerShell (Windows)
cd frontend\oat
.\download.ps1
```

## Licenses

- **Datastar** — MIT License (https://github.com/starfederation/datastar)
- **Oat.ink** — MIT License (https://oat.ink)