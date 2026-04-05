# Download Oat.ink CSS/JS framework
# Usage: .\download.ps1 [-Version <version>]
param(
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

$BaseUrl = "https://oat.ink"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "Downloading Oat.ink $Version..."

$CssFile = Join-Path $ScriptDir "oat.min.css"
$JsFile = Join-Path $ScriptDir "oat.min.js"

try {
    Invoke-WebRequest -Uri "$BaseUrl/oat.min.css" -OutFile $CssFile -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/oat.min.js" -OutFile $JsFile -UseBasicParsing
} catch {
    Write-Host "ERROR: Failed to download Oat.ink files"
    Write-Host $_.Exception.Message
    exit 1
}

# Copy to v2/frontend/ for go:embed
$V2Frontend = Join-Path $ProjectRoot "v2\frontend"
Copy-Item $CssFile (Join-Path $V2Frontend "oat.min.css") -Force
Copy-Item $JsFile (Join-Path $V2Frontend "oat.min.js") -Force

$CssSize = (Get-Item $CssFile).Length
$JsSize = (Get-Item $JsFile).Length

Write-Host "Downloaded oat.min.css ($CssSize bytes)"
Write-Host "Downloaded oat.min.js ($JsSize bytes)"
Write-Host "Copied to v2/frontend/"
Write-Host "Done."