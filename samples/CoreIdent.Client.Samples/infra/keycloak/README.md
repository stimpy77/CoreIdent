# Keycloak (local)

This folder contains a minimal Docker Compose setup for running Keycloak locally for OpenID Connect testing.

The Keycloak container image is pinned (see `docker-compose.yml`) for reproducibility.

## Quick start

From the repo root:

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-up.ps1
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-configure.ps1
```

Then run the sample against Keycloak:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak
```

## Workflow

### 1) Start Keycloak

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-up.ps1
```

Keycloak will be available at:

- Admin UI: `http://localhost:8080/admin`
- Realm issuer base (authority): `http://localhost:8080/realms/coreident-dev/`

### 2) Configure realm + client (repeatable)

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-configure.ps1
```

This script is intended to be safe to run repeatedly. It ensures:

- Realm: `coreident-dev`
- User: `alice` / `Passw0rd!`
- OIDC client (confidential): `coreident-client` / `coreident-client-secret`
- Redirect URI: `http://localhost:7890/callback/`

It also configures Keycloak's **valid post-logout redirect URIs** to allow:

- `http://localhost:7890/logout/`

### 3) Run the interactive sample

Basic login:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak
```

Expected behavior:

- A browser window opens to Keycloak login.
- Login with `alice` / `Passw0rd!`.
- The console prints user info and `OK`.

### Optional: refresh token exercise

If `offline_access` is requested and the provider issues a refresh token, the sample will attempt a refresh via `LoginSilentAsync()`.

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak --scopes "openid profile email offline_access"
```

### Optional: logout exercise

If Keycloak advertises `end_session_endpoint`, the sample will attempt logout when `--post-logout-redirect-uri` is provided:

```pwsh
dotnet run --project samples/CoreIdent.Client.Samples -- keycloak --post-logout-redirect-uri "http://localhost:7890/logout/"
```

Expected behavior:

- The sample prints `Attempting logout ...` and completes with `OK`.

## Troubleshooting

### "Invalid parameter: redirect_uri"

This means the `redirect_uri` in the authorization request did not exactly match a configured client redirect URI.

Verify the client is configured with:

- `http://localhost:7890/callback/`

Re-run:

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-configure.ps1
```

### "Invalid redirect uri" (during logout)

Keycloak validates `post_logout_redirect_uri` against a separate allowlist (valid post-logout redirect URIs).

Re-run:

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-configure.ps1
```

## Cleanup

```pwsh
pwsh ./samples/CoreIdent.Client.Samples/scripts/keycloak-down.ps1
```

## Credentials (dev-only)

- Admin user: `admin`
- Admin password: `admin`

The configure script creates:

- Realm: `coreident-dev`
- User: `alice` / `Passw0rd!`
- OIDC client (confidential): `coreident-client` / `coreident-client-secret`
- Redirect URI: `http://localhost:7890/callback/`

> These values are intentionally **not secure** and are intended for local development only.
