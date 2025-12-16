# Passkeys (WebAuthn) Setup Guide

This guide covers configuring CoreIdent passkey endpoints (WebAuthn/FIDO2) using the `CoreIdent.Passkeys.AspNetIdentity` package.

## At a glance

- **Packages:** `CoreIdent.Passkeys.AspNetIdentity` (plus `CoreIdent.Storage.EntityFrameworkCore` if you want EF Core persistence)
- **Map endpoints:** `app.MapCoreIdentPasskeyEndpoints()`
- **Endpoints:**
  - `POST /auth/passkey/register/options`
  - `POST /auth/passkey/register/complete`
  - `POST /auth/passkey/authenticate/options`
  - `POST /auth/passkey/authenticate/complete`
- **Auth requirements:**
  - `register/*` requires a **CoreIdent bearer token** (user must already be authenticated)
  - `authenticate/*` is used to sign-in (server returns CoreIdent tokens)

## Prerequisites

- Your app must run on **HTTPS**.
- In development, use `https://localhost` (or a trusted dev cert for your hostname).
- Passkeys require a **secure context** and **WebAuthn-capable browser**.

## Packages

CoreIdent passkeys are implemented as a separate package to keep `CoreIdent.Core` free of ASP.NET Identity dependencies.

- `CoreIdent.Passkeys`
- `CoreIdent.Passkeys.AspNetIdentity`

If you want persistence:

- `CoreIdent.Storage.EntityFrameworkCore`

## Server configuration

### Minimal configuration (in-memory credential store)

```csharp
builder.Services.AddCoreIdent();

// Required for CoreIdent resource-owner flows (if you use /auth/login or /auth/register)
builder.Services.AddAspNetIdentityPasswordHasher();

// Passkeys
builder.Services.AddPasskeys(options =>
{
    // Used when issuing CoreIdent tokens in /auth/passkey/authenticate/complete
    options.ClientId = "passkey";

    // RP ID (domain) used for WebAuthn
    // If null, ASP.NET Identity uses the server origin.
    options.RelyingPartyId = "localhost";

    // Browser hint (may be ignored by the browser)
    options.ChallengeTimeout = TimeSpan.FromMinutes(5);

    // Challenge length
    options.ChallengeSize = 32;
});

app.MapCoreIdentEndpoints();
app.MapCoreIdentPasskeyEndpoints();
```

### Persistence (EF Core)

If your host app uses EF Core stores, passkey credentials will be persisted via `EfPasskeyCredentialStore`.

```csharp
builder.Services.AddDbContext<CoreIdentDbContext>(...);

// Registers EF stores including the passkey credential store.
builder.Services.AddEntityFrameworkCoreStores();
```

## Endpoints

CoreIdent exposes 4 passkey endpoints:

- `POST /auth/passkey/register/options`
- `POST /auth/passkey/register/complete`
- `POST /auth/passkey/authenticate/options`
- `POST /auth/passkey/authenticate/complete`

### Auth requirements

- `register/*` endpoints require a **CoreIdent bearer token** (user must already be authenticated).
- `authenticate/*` endpoints are used to sign-in.

## Browser requirements

- WebAuthn support is required (modern Chromium / Safari / Firefox).
- HTTPS is required.
- Some platforms impose additional constraints:
  - Embedded WebViews may have limitations.
  - Cross-origin iframes may be blocked.

## JavaScript integration examples

The examples below intentionally avoid framework-specific code.

### Register a passkey

```js
// 1) Ask the server for creation options
const optionsRes = await fetch('/auth/passkey/register/options', {
  method: 'POST',
  headers: {
    'Accept': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  }
});
const creationOptionsJson = await optionsRes.json();

// 2) Convert JSON into a PublicKeyCredentialCreationOptions instance
const creationOptions = PublicKeyCredential.parseCreationOptionsFromJSON(creationOptionsJson);

// 3) Create credentials
const credential = await navigator.credentials.create({ publicKey: creationOptions });

// 4) Serialize back to JSON
const credentialJson = JSON.stringify(credential);

// 5) Complete registration
await fetch('/auth/passkey/register/complete', {
  method: 'POST',
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({ credentialJson })
});
```

### Authenticate with a passkey

```js
// 1) Ask the server for assertion options
const optionsRes = await fetch('/auth/passkey/authenticate/options', {
  method: 'POST',
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ username: null })
});
const requestOptionsJson = await optionsRes.json();

// 2) Convert JSON into a PublicKeyCredentialRequestOptions instance
const requestOptions = PublicKeyCredential.parseRequestOptionsFromJSON(requestOptionsJson);

// 3) Request assertion
const credential = await navigator.credentials.get({ publicKey: requestOptions });

// 4) Serialize back to JSON
const credentialJson = JSON.stringify(credential);

// 5) Complete authentication (server returns CoreIdent tokens)
const completeRes = await fetch('/auth/passkey/authenticate/complete', {
  method: 'POST',
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ credentialJson })
});

if (!completeRes.ok) {
  throw new Error('Passkey authentication failed');
}

const tokens = await completeRes.json();
// tokens.accessToken, tokens.refreshToken, tokens.expiresIn
```

## Notes

- CoreIdent stores passkey metadata (`CreatedAt`, `Transports`, `AttestationObject`, `ClientDataJson`) so future assertions can validate and update signature counters correctly.
- The WebAuthn browser API is strict about calling methods with the correct `this` binding. If you run into errors around `toJSON`, use the `PublicKeyCredential.*FromJSON` helpers as shown above.
