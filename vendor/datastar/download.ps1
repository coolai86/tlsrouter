# Download Datastar JS library
# Usage: .\download.ps1 [-Version <version>]
param(
    [string]$Version = "v1.0.0-RC.7"
)

$ErrorActionPreference = "Stop"

$BaseVersion = $Version -replace '^v', ''
$BaseUrl = "https://raw.githubusercontent.com/starfederation/datastar/$BaseVersion/bundles"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "Downloading Datastar $Version..."

$OutputFile = Join-Path $ScriptDir "datastar.js"
$Url = "$BaseUrl/datastar.js"

try {
    Invoke-WebRequest -Uri $Url -OutFile $OutputFile -UseBasicParsing
} catch {
    Write-Host "ERROR: Failed to download datastar.js"
    Write-Host $_.Exception.Message
    exit 1
}

# Copy to v2/vendor/ for go:embed
$V2Vendor = Join-Path $ProjectRoot "v2\vendor"
$V2OutputFile = Join-Path $V2Vendor "datastar.js"
Copy-Item $OutputFile $V2OutputFile -Force

$FileSize = (Get-Item $OutputFile).Length
Write-Host "Downloaded datastar.js ($FileSize bytes)"
Write-Host "Copied to v2/vendor/datastar.js"
Write-Host "Done."