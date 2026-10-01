<#
  Deploys the static project site (site/) to Vercel as a production build.

  Usage:
    .\deploy.ps1                          # uses $env:VERCEL_TOKEN
    .\deploy.ps1 -Token "<your token>"

  Get a token at https://vercel.com/account/tokens (never commit it).
  The token is passed to the CLI on the command line only.
#>
param(
    [string]$Token = $env:VERCEL_TOKEN,
    [string]$Project = "lifevault",
    [switch]$Preview
)

$ErrorActionPreference = "Stop"

if (-not $Token) {
    Write-Host "No Vercel token found." -ForegroundColor Yellow
    Write-Host "Set one with:  `$env:VERCEL_TOKEN = '<token>'   or pass -Token '<token>'"
    exit 1
}

if (-not (Test-Path (Join-Path $PSScriptRoot "site\index.html"))) {
    Write-Host "site\index.html not found - run this from the repo root." -ForegroundColor Red
    exit 1
}

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) {
    foreach ($candidate in @("$env:ProgramFiles\nodejs\node.exe")) {
        if (Test-Path $candidate) { $env:PATH = "$(Split-Path $candidate);$env:PATH"; break }
    }
}

$args = @("yes", "vercel@latest", "deploy", "--cwd", (Join-Path $PSScriptRoot "site"),
          "--project", $Project, "--yes", "--non-interactive", "--json",
          "--token", $Token)
if (-not $Preview) { $args += "--prod" }

Write-Host "Deploying site/ to Vercel project '$Project' ..." -ForegroundColor Cyan
$out = & npx @args
if ($LASTEXITCODE -ne 0) {
    Write-Host "Deploy failed (exit $LASTEXITCODE)." -ForegroundColor Red
    exit $LASTEXITCODE
}

# Keep the short alias pointing at the newest production deployment.
$alias = "lifevaultapp.vercel.app"
$deployment = $null
try { $deployment = ($out | Select-String -Pattern '"productionUrl":\s*"([^"]+)"').Matches[0].Groups[1].Value } catch { }
if (-not $deployment) {
    try { $deployment = ($out | Select-String -Pattern '"url":\s*"([^"]+)"').Matches[0].Groups[1].Value } catch { }
}
if ($deployment -and $alias) {
    Write-Host "Pointing https://$alias at $deployment ..." -ForegroundColor Cyan
    & npx @("yes", "vercel@latest", "alias", "set", $deployment, $alias, "--non-interactive")
}
