#!/usr/bin/env pwsh
[CmdletBinding()]
param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$composeFile = Join-Path $PSScriptRoot '..' 'infra' 'keycloak' 'docker-compose.yml'

if (-not (Test-Path $composeFile)) {
  throw "docker-compose.yml not found at: $composeFile"
}

Write-Host "Stopping Keycloak (docker compose)..."

if (-not $Force) {
  $answer = Read-Host "Proceed? (y/N)"
  if ($answer -notin @('y','Y','yes','YES')) {
    Write-Host "Cancelled."
    exit 1
  }
}

docker compose -f $composeFile down
if ($LASTEXITCODE -ne 0) { throw "docker compose down failed" }

Write-Host "Stopped."