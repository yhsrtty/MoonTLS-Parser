param(
  [switch]$SkipMooncakes
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Require-File($path) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "Missing required file: $path"
  }
}

Write-Host "MoonTLS-Parser acceptance verification"
Write-Host "Root: $root"

Require-File "README.md"
Require-File "LICENSE"
Require-File "CHANGELOG.md"
Require-File "moon.mod"
Require-File "moon.pkg"
Require-File ".github/workflows/ci.yml"
Require-File "docs/source-attribution.md"
Require-File "docs/acceptance-checklist.md"

Write-Host "Running moon check..."
moon update
moon check --warn-list +73

Write-Host "Running moon test..."
moon test

Write-Host "Generating public API summary..."
moon info

Write-Host "Running demo..."
moon run --target native cmd/main

$trackedMoon = @(git ls-files "*.mbt" "*.mbti")
$lineCount = 0
foreach ($file in $trackedMoon) {
  if (Test-Path -LiteralPath $file) {
    $lineCount += (Get-Content -LiteralPath $file).Count
  }
}
Write-Host "Tracked MoonBit/API lines: $lineCount"

$commitCount = (git rev-list --count HEAD)
Write-Host "Commit history count: $commitCount"

$defaultBranch = git symbolic-ref --short HEAD
Write-Host "Current branch: $defaultBranch"

if (-not $SkipMooncakes) {
  Write-Host "Checking Mooncakes package availability..."
  $url = "https://mooncakes.io/api/v0/modules/yhsrtty/moontls-parser"
  $status = curl.exe -L -s -o NUL -w "%{http_code}" $url
  Write-Host "Mooncakes status: $status ($url)"
}

Write-Host "Acceptance verification complete."

