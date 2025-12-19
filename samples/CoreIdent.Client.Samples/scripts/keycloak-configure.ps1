#!/usr/bin/env pwsh
[CmdletBinding()]
param(
  [switch]$Force,
  [string]$Realm = 'coreident-dev',
  [string]$ClientId = 'coreident-client',
  [string]$ClientSecret = 'coreident-client-secret',
  [string]$RedirectUri = 'http://localhost:7890/callback/',
  [string]$PostLogoutRedirectUri = '',
  [string]$UserName = 'alice',
  [string]$UserEmail = 'alice@example.com',
  [string]$UserPassword = 'Passw0rd!'
)

$ErrorActionPreference = 'Stop'

$composeFile = Join-Path $PSScriptRoot '..' 'infra' 'keycloak' 'docker-compose.yml'
if (-not (Test-Path $composeFile)) {
  throw "docker-compose.yml not found at: $composeFile"
}

function Wait-TcpPort {
  param(
    [Parameter(Mandatory=$true)][string]$HostName,
    [Parameter(Mandatory=$true)][int]$Port,
    [int]$TimeoutSeconds = 180
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $task = $client.ConnectAsync($HostName, $Port)
      if ($task.Wait(1000)) {
        $client.Dispose()
        return
      }
      $client.Dispose()
    } catch {
      # ignore
    }

    Start-Sleep -Seconds 1
  }

  throw "Timed out waiting for $($HostName):$Port"
}

function Invoke-KcAdm {
  param(
    [Parameter(Mandatory=$true)][string[]]$Args
  )

  $cmd = @('compose','-f',$composeFile,'exec','-T','keycloak','/opt/keycloak/bin/kcadm.sh') + $Args

  # Capture stdout and stderr separately to avoid interleaving corrupting JSON,
  # while still preserving diagnostics when Keycloak writes to stderr.
  $stdoutFile = [System.IO.Path]::GetTempFileName()
  $stderrFile = [System.IO.Path]::GetTempFileName()

  try {
    & docker @cmd 1> $stdoutFile 2> $stderrFile
    $code = $LASTEXITCODE

    $stdout = (Get-Content -LiteralPath $stdoutFile -Raw)
    $stderr = (Get-Content -LiteralPath $stderrFile -Raw)
  }
  finally {
    Remove-Item -LiteralPath $stdoutFile -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrFile -ErrorAction SilentlyContinue
  }

  # Prefer stdout if present; otherwise fall back to stderr (some tools emit JSON to stderr).
  $output = if (-not [string]::IsNullOrWhiteSpace($stdout)) { $stdout } else { $stderr }

  return [pscustomobject]@{ ExitCode = $code; Output = ($output ?? '').Trim(); StdOut = ($stdout ?? '').Trim(); StdErr = ($stderr ?? '').Trim() }
}

function Get-FirstJsonValueText {
  param(
    [Parameter(Mandatory=$true)][string]$Text
  )

  $t = $Text.Trim()
  if ([string]::IsNullOrWhiteSpace($t)) {
    return $null
  }

  # Find first JSON start.
  $idxObj = $t.IndexOf('{')
  $idxArr = $t.IndexOf('[')
  $idx = @($idxObj, $idxArr) | Where-Object { $_ -ge 0 } | Sort-Object | Select-Object -First 1

  if ($null -eq $idx) {
    throw "Expected JSON but could not find '{' or '[' in output: $t"
  }

  $startChar = $t[$idx]
  $endChar = if ($startChar -eq '{') { '}' } else { ']' }

  $depth = 0
  $inString = $false
  $escape = $false

  for ($i = $idx; $i -lt $t.Length; $i++) {
    $ch = $t[$i]

    if ($inString) {
      if ($escape) {
        $escape = $false
        continue
      }

      if ($ch -eq '\\') {
        $escape = $true
        continue
      }

      if ($ch -eq '"') {
        $inString = $false
      }

      continue
    }

    if ($ch -eq '"') {
      $inString = $true
      continue
    }

    if ($ch -eq $startChar) {
      $depth++
      continue
    }

    if ($ch -eq $endChar) {
      $depth--
      if ($depth -eq 0) {
        return $t.Substring($idx, ($i - $idx + 1))
      }
      continue
    }
  }

  throw "Expected JSON starting at index $idx but did not find a complete JSON value."
}

function ConvertFrom-JsonLenient {
  param(
    [Parameter(Mandatory=$true)][string]$Text
  )

  $json = Get-FirstJsonValueText -Text $Text
  if ($null -eq $json) {
    return $null
  }

  # Use -AsHashtable to handle dotted property names like "access.view" that Keycloak returns.
  $val = ($json | ConvertFrom-Json -AsHashtable)

  # Normalize to an array of items.
  # - Keycloak often returns JSON arrays. With -AsHashtable, PowerShell may represent arrays as a hashtable
  #   with integer keys (0..n-1).
  # - If a single object is returned, it will be a hashtable with string keys.
  if ($val -is [System.Collections.IDictionary]) {
    $keys = @($val.Keys)
    if ($keys.Count -gt 0 -and ($keys | Select-Object -First 1) -is [int]) {
      $sorted = $keys | Sort-Object
      return @($sorted | ForEach-Object { $val[$_] })
    }

    return @($val)
  }

  if ($val -is [array]) {
    return $val
  }

  return @($val)
}

Write-Host "Configuring Keycloak via kcadm (repeatable)..."
Write-Host "  Realm:        $Realm"
Write-Host "  ClientId:     $ClientId (confidential)"
Write-Host "  RedirectUri:  $RedirectUri"
Write-Host "  User:         $UserName ($UserEmail)"
Write-Host "  Admin:        http://localhost:8080/admin (admin/admin)"

if ([string]::IsNullOrWhiteSpace($PostLogoutRedirectUri)) {
  $ru = [Uri]::new($RedirectUri, [UriKind]::Absolute)
  $PostLogoutRedirectUri = "{0}://{1}:{2}/logout/" -f $ru.Scheme, $ru.Host, $ru.Port
}

Write-Host "  PostLogout:   $PostLogoutRedirectUri"

if (-not $Force) {
  $answer = Read-Host "Proceed? (y/N)"
  if ($answer -notin @('y','Y','yes','YES')) {
    Write-Host "Cancelled."
    exit 1
  }
}

Write-Host "Waiting for Keycloak port 8080..."
Wait-TcpPort -HostName '127.0.0.1' -Port 8080 -TimeoutSeconds 240

Write-Host "Logging into kcadm..."
$login = Invoke-KcAdm -Args @('config','credentials','--server','http://localhost:8080','--realm','master','--user','admin','--password','admin')
if ($login.ExitCode -ne 0) { throw "kcadm login failed: $($login.Output)" }

# Ensure realm exists
Write-Host "Ensuring realm '$Realm' exists..."
$getRealm = Invoke-KcAdm -Args @('get',"realms/$Realm")
if ($getRealm.ExitCode -ne 0) {
  $createRealm = Invoke-KcAdm -Args @('create','realms','-s',"realm=$Realm",'-s','enabled=true')
  if ($createRealm.ExitCode -ne 0) { throw "Failed to create realm: $($createRealm.Output)" }
}

# Ensure user exists
Write-Host "Ensuring user '$UserName' exists..."
$getUsers = Invoke-KcAdm -Args @('get','users','-r',$Realm,'-q',"username=$UserName")
if ($getUsers.ExitCode -ne 0) { throw "Failed to query users: $($getUsers.Output)" }
$usersJson = ConvertFrom-JsonLenient -Text $getUsers.Output
if (-not $usersJson -or $usersJson.Count -eq 0) {
  $createUser = Invoke-KcAdm -Args @('create','users','-r',$Realm,'-s',"username=$UserName",'-s','enabled=true','-s',"email=$UserEmail",'-s','emailVerified=true')
  if ($createUser.ExitCode -ne 0) { throw "Failed to create user: $($createUser.Output)" }
}

Write-Host "Setting password for user '$UserName' (dev-only)..."
$setPwd = Invoke-KcAdm -Args @('set-password','-r',$Realm,'--username',$UserName,'--new-password',$UserPassword,'--temporary=false')
if ($setPwd.ExitCode -ne 0) { throw "Failed to set password: $($setPwd.Output)" }

# Ensure client exists
Write-Host "Ensuring client '$ClientId' exists..."
$getClients = Invoke-KcAdm -Args @('get','clients','-r',$Realm,'-q',"clientId=$ClientId")
if ($getClients.ExitCode -ne 0) { throw "Failed to query clients: $($getClients.Output)" }
$clientsJson = ConvertFrom-JsonLenient -Text $getClients.Output

if (-not $clientsJson -or $clientsJson.Count -eq 0) {
  $redirectUris = (ConvertTo-Json @($RedirectUri) -Compress)
  $webOrigins = (ConvertTo-Json @('http://localhost:7890') -Compress)

  $createClient = Invoke-KcAdm -Args @(
    'create','clients','-r',$Realm,
    '-s',"clientId=$ClientId",
    '-s','enabled=true',
    '-s','protocol=openid-connect',
    '-s','publicClient=false',
    '-s','standardFlowEnabled=true',
    '-s','directAccessGrantsEnabled=false',
    '-s',"redirectUris=$redirectUris",
    '-s',"webOrigins=$webOrigins"
  )
  if ($createClient.ExitCode -ne 0) { throw "Failed to create client: $($createClient.Output)" }

  $getClients = Invoke-KcAdm -Args @('get','clients','-r',$Realm,'-q',"clientId=$ClientId")
  if ($getClients.ExitCode -ne 0) { throw "Failed to re-query clients: $($getClients.Output)" }
  $clientsJson = ConvertFrom-JsonLenient -Text $getClients.Output
}

$lastClientsOutput = $getClients.Output

if (-not $clientsJson -or $clientsJson.Count -eq 0) {
  throw "Expected Keycloak to return the client after query/create, but got no results. Output was: $lastClientsOutput"
}

$firstClient = $clientsJson | Select-Object -First 1
$clientInternalId = $null
if ($firstClient -is [System.Collections.IDictionary]) {
  $clientInternalId = $firstClient['id']
}
if (-not $clientInternalId) { throw "Could not determine Keycloak internal client id." }

Write-Host "Setting client secret for '$ClientId' (dev-only)..."
$updateSecret = Invoke-KcAdm -Args @('update',"clients/$clientInternalId",'-r',$Realm,'-s',"secret=$ClientSecret")
if ($updateSecret.ExitCode -ne 0) { throw "Failed to set client secret: $($updateSecret.Output)" }

Write-Host "Setting valid post-logout redirect URIs for '$ClientId' (dev-only)..."
$postLogoutAttr = 'attributes."post.logout.redirect.uris"=' + $PostLogoutRedirectUri
$updatePostLogout = Invoke-KcAdm -Args @('update',"clients/$clientInternalId",'-r',$Realm,'-s',$postLogoutAttr)
if ($updatePostLogout.ExitCode -ne 0) { throw "Failed to set post-logout redirect URIs: $($updatePostLogout.Output)" }

Write-Host "Done. Values to use:" 
Write-Host "  Authority:      http://localhost:8080/realms/$Realm/"
Write-Host "  ClientId:       $ClientId"
Write-Host "  ClientSecret:   $ClientSecret"
Write-Host "  RedirectUri:    $RedirectUri"
Write-Host "  PostLogoutUri:  $PostLogoutRedirectUri"
Write-Host "  User:           $UserName / $UserPassword"
