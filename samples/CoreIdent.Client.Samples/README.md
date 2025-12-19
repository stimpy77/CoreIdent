# CoreIdent.Client samples

This folder contains a small, scriptable harness for exercising `CoreIdent.Client` against:

- **Keycloak** (via Docker)
- **CoreIdent** (via a local sample host)

The intent is to document a repeatable “how we tested it” workflow, while keeping everything useful as public samples.

## Prerequisites

- .NET 10 SDK
- PowerShell 7+
- Docker (for Keycloak)

## 1) Keycloak (interactive)

### Optional: refresh token exercise
If you include `offline_access` in requested scopes **and** the provider issues a refresh token, the sample will attempt a refresh.

Example:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak --scopes "openid profile email offline_access"
```

### Optional: logout exercise
If the provider advertises `end_session_endpoint`, you can ask the sample to attempt logout by providing a post-logout redirect URI:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak --post-logout-redirect-uri "http://localhost:7890/logout/"
```

You may need to also configure the provider to allow that post-logout redirect URI.

### Start + configure

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-up.ps1
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-configure.ps1
```

This configures (dev-only):

- Realm: `coreident-dev`
- User: `alice` / `Passw0rd!`
- Client (confidential): `coreident-client` / `coreident-client-secret`
- Redirect URI: `http://localhost:7890/callback/`

### Run the sample

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak
```

## 2) CoreIdent (headless, no browser)

### CI-style mode
Use `--ci` for minimal output and non-interactive intent:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- coreident --ci
```

This uses a local CoreIdent host that:

- Sets `Issuer` to match its local URL (so discovery advertises usable endpoints)
- Uses a test-header auth scheme for `/auth/authorize` (no cookies/UI required)

### Start the server sample

```pwsh
dotnet run --project samples/CoreIdent.Server.Samples
```

It listens on `http://localhost:5080`.

### Run the client sample against it

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- coreident
```

### Inspect roles + delegated claims

The CoreIdent server sample exposes non-standard user claims via the OIDC `userinfo` endpoint only when the client requests the `custom_claims` scope.

Example:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- coreident --scopes "openid profile email custom_claims" --dump-claims
```

`--dump-claims` prints claims from multiple sources:

- **ID Token Claims**: validated claims from the ID token (if an ID token was issued)
- **UserInfo Claims**: claims returned by `userinfo` (scope-gated)
- **Merged Claims (GetUserAsync)**: the client's merged principal (ID token as base + userinfo added, no overwrites)
- **Access Token**: decoded claims if the access token is a JWT; otherwise marked as opaque

## Troubleshooting

### Redirect URI must be loopback + include trailing slash
`CoreIdent.Client`’s default `SystemBrowserLauncher` listens via `HttpListener` and expects a loopback redirect URI.

Use something like:

- `http://localhost:7890/callback/`

### CoreIdent discovery endpoints are issuer-based
CoreIdent’s discovery document advertises absolute endpoint URLs based on `CoreIdentOptions.Issuer`. If `Issuer` is not your actual local URL, clients will try to call the wrong host.
