# CoreIdent Code Review — Deferred Findings

**Date:** 2026-03-15
**Scope:** Comprehensive 4-pass code review across all 7 feature areas (Core Models/Stores, Token Lifecycle, OAuth/OIDC Flows, Auth Endpoints, Passkeys & Providers, Client Libraries, Infrastructure & Tooling).
**Reviewers:** 7 parallel code-reviewer agents, looped until convergence.
**Commits from review:** `08f1b43`, `40f824b`, `936ae4a` (29 + 8 + 5 = 42 fixes applied and committed).

This document captures findings that were **identified but not fixed** because they require design decisions, interface changes, schema migrations, or breaking changes that should not be applied without deliberate planning.

---

## A. Access Tokens in Email Redirect URL (HIGH)

**File:** `src/CoreIdent.Core/Endpoints/PasswordlessEmailEndpointsExtensions.cs`, lines 208-213
**Category:** Security — token exfiltration via query string

### Current behavior

When `PasswordlessEmailOptions.SuccessRedirectUrl` is configured (the expected production path), the email magic-link verify handler appends access and refresh tokens as **query parameters**:

```csharp
var separator = successRedirect.Contains('?', StringComparison.Ordinal) ? '&' : '?';
var url = $"{successRedirect}{separator}access_token={Uri.EscapeDataString(accessToken)}&refresh_token={Uri.EscapeDataString(refreshTokenHandle)}&token_type=Bearer&expires_in={(int)options.AccessTokenLifetime.TotalSeconds}";
return Results.Redirect(url);
```

### Why this is a problem

Tokens in query strings appear in:
- Server-side HTTP access logs at the redirect target
- Browser history
- `Referer` headers on any subsequent navigation from the landing page
- Shared proxy/CDN logs

This violates OAuth 2.0 Security BCP (RFC 9700 §4.3.2) and is the exact reason the implicit flow was deprecated in OAuth 2.1. The SMS OTP verify handler (`PasswordlessSmsEndpointsExtensions.cs`) correctly returns tokens as a JSON body — email is the only path with this issue.

### Recommended fix

**Option 1 (minimal, low effort):** Change `?` to `#` — use URL fragment instead of query string. Tokens never reach the server; the SPA reads them from `window.location.hash`. One-line change.

**Option 2 (ideal, medium effort):** Return a short-lived one-time code in the redirect, then the client exchanges it for tokens via a POST (mirroring authorization_code flow). Requires a new code store entry and exchange endpoint.

### Contrast with SMS path

`PasswordlessSmsEndpointsExtensions.cs` lines 207-222 returns tokens as JSON body — no redirect, no query string exposure. The email path should converge to a similar pattern.

### Fallback path

When `SuccessRedirectUrl` is **not** configured (line 218), the handler returns a plain HTML page with no tokens at all — so the redirect is the only programmatic token delivery mechanism.

---

## B. OTP Verify-Attempt Lockout (HIGH)

**File:** `src/CoreIdent.Core/Stores/InMemory/InMemoryPasswordlessTokenStore.cs`, method `ValidateAndConsumeAsync` (lines 90-132)
**Endpoints:** `PasswordlessSmsEndpointsExtensions.cs` `POST /auth/passwordless/sms/verify`, `PasswordlessEmailEndpointsExtensions.cs` `GET /auth/passwordless/email/verify`
**Category:** Security — brute-force attack on OTP

### Current behavior

**Issuance** rate limiting exists: `CreateTokenAsync` calls `EnforceRateLimit` (lines 150-169), which limits how many OTPs can be **sent** per hour using `MaxAttemptsPerHour`, keyed by `$"{tokenType}:{recipient}"`.

**Verification** has no rate limiting at all. `ValidateAndConsumeAsync` hashes the submitted token, looks it up in `_tokensByHash`, checks expiry and consumed flag, and returns. No counter of failed attempts, no lockout, no delay.

### Attack surface

A 6-digit OTP (`GenerateOtp` at line 199-201) has 1,000,000 possible values. Default lifetime is 5-10 minutes. An attacker who knows the target phone number can submit all 1M values before the OTP expires. The issuance rate limit does not help because the attacker is not the one who requested the OTP — the legitimate user is.

Email magic links are NOT affected (32 random bytes = 256 bits of entropy, computationally infeasible to brute-force).

### Recommended fix

Add a per-token (or per-recipient+tokenType) failed-attempt counter:
- On each failed `ValidateAndConsumeAsync` call, increment a counter keyed by `tokenHash` or `$"{tokenType}:{recipient}"`
- After N failures (configurable, default 5), invalidate the OTP (set `Consumed = true` or remove from store)
- The EF store (`EfPasswordlessTokenStore`) needs a similar column or side table

This requires adding a `ConcurrentDictionary<string, int>` to `InMemoryPasswordlessTokenStore` and a configurable `MaxVerifyAttempts` option.

### Interface impact

No `IPasswordlessTokenStore` interface change strictly needed — the counter can be internal to each implementation. However, a `MaxVerifyAttempts` config property should be added to `PasswordlessEmailOptions` and `PasswordlessSmsOptions`.

---

## C. UserInfo Claims Method (LOW — No Fix Needed)

**File:** `src/CoreIdent.Core/Endpoints/UserInfoEndpointExtensions.cs`, line 115
**Category:** OIDC spec compliance — informational only

### Current behavior

```csharp
var customClaims = await customClaimsProvider.GetIdTokenClaimsAsync(claimsContext, ct);
```

### Why this is actually correct

OIDC Core §5.3 defines the UserInfo endpoint as returning the same class of claims as the ID token (user-facing profile claims). `ICustomClaimsProvider` has two methods:
- `GetAccessTokenClaimsAsync` — for access token claims (service-level)
- `GetIdTokenClaimsAsync` — for ID token / user-facing claims

Calling `GetIdTokenClaimsAsync` is semantically correct. The default `NullCustomClaimsProvider` returns empty for both, so no practical divergence exists.

### Recommendation

Add a code comment at line 115 explaining the rationale. No code change needed.

---

## D. Refresh Token Rotation Atomicity (MEDIUM)

**File:** `src/CoreIdent.Core/Endpoints/TokenEndpointExtensions.cs`, lines 477-547
**Category:** Reliability — user lockout on crash

### Current sequence

1. **Line 477:** `await refreshTokenStore.ConsumeAsync(tokenRequest.RefreshToken, ct)` — marks old token consumed
2. **Lines 528-533:** `await tokenService.CreateJwtAsync(...)` — signs new access token (in memory)
3. **Lines 536-545:** Constructs new `CoreIdentRefreshToken` object
4. **Line 547:** `await refreshTokenStore.StoreAsync(newRefreshToken, ct)` — persists new refresh token

### Crash window

If the process crashes after step 1 but before step 4:
- Old refresh token is permanently consumed
- New refresh token was never stored
- User is silently logged out with no recovery path (must re-authenticate)

### Severity context

This is a **known and accepted limitation** of single-store refresh token rotation without distributed transactions. Most OAuth servers (IdentityServer, Duende, Auth0) have the same behavior. The crash probability between two sequential store operations is very low, but the consequence is user-visible.

### Possible fixes (in order of complexity)

1. **Compensating rollback:** Wrap the sequence in try/catch; if `StoreAsync` fails, attempt to un-consume the old token. Requires adding `UnconsumeAsync` to `IRefreshTokenStore`.
2. **DB transaction:** For the EF store, wrap consume + store in a single `IDbContextTransaction`. The in-memory store would need equivalent simulation.
3. **Atomic exchange:** Add `Task<CoreIdentRefreshToken?> ExchangeAsync(string oldHandle, CoreIdentRefreshToken newToken, CancellationToken ct)` to `IRefreshTokenStore` that atomically marks old consumed and stores new.

### Interface impact

All three options require changes to `IRefreshTokenStore` (new methods or transaction support). This is a breaking change for third-party store implementations.

---

## E. EcdsaSigningKeyProvider Handle Leak (MEDIUM)

**File:** `src/CoreIdent.Core/Services/EcdsaSigningKeyProvider.cs`, lines 49-64
**Category:** Resource leak — native cryptographic handles

### Current behavior

```csharp
public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync(CancellationToken ct = default)
{
    var key = _signingKey.Value;
    // ... creates a NEW ECDsa instance on every call:
    var publicEcdsa = ECDsa.Create();
    publicEcdsa.ImportSubjectPublicKeyInfo(key.ECDsa.ExportSubjectPublicKeyInfo(), out _);
    var publicKey = new ECDsaSecurityKey(publicEcdsa) { KeyId = _keyId.Value };
    // ...
}
```

### How often this is called

Every token validation (UserInfo, introspection, revocation, protected endpoints) calls `GetValidationKeysAsync`. This is a **per-request** allocation of a native `ECDsa` handle. The signing key itself is already `Lazy<>` and stable — only the public validation copy is re-created each time.

### Impact

On Windows: `ECDsa` backed by CNG acquires a kernel-level cryptographic handle per call. On Linux (OpenSSL): holds an `EVP_PKEY*`. Both are eventually collected by the GC finalizer, but under load they pile up proportional to request rate, causing handle pressure and GC pressure.

The `RsaSigningKeyProvider` does NOT have this problem — it caches the public RSA key and reuses it.

### Recommended fix

Cache the public-only `ECDsaSecurityKey` in a `Lazy<ECDsaSecurityKey>` field, consistent with how `_signingKey` is already cached:

```csharp
private readonly Lazy<ECDsaSecurityKey> _publicKey;

// In constructor:
_publicKey = new Lazy<ECDsaSecurityKey>(() =>
{
    var pub = ECDsa.Create();
    pub.ImportSubjectPublicKeyInfo(_signingKey.Value.ECDsa.ExportSubjectPublicKeyInfo(), out _);
    return new ECDsaSecurityKey(pub) { KeyId = _keyId.Value };
});

// In GetValidationKeysAsync:
return Task.FromResult<IEnumerable<SecurityKeyInfo>>(
    [new SecurityKeyInfo(_keyId.Value, _publicKey.Value, expiresAt: null)]);

// In Dispose:
if (_publicKey.IsValueCreated) _publicKey.Value.ECDsa?.Dispose();
```

**Effort:** Low. Non-breaking. No interface changes.

---

## F. Client Library Magic Strings (LOW)

**File:** `src/CoreIdent.Client/CoreIdentClient.cs` (many locations)
**Category:** Code quality — CLAUDE.md "no magic strings" guideline

### Current state

~30 inline string literals for OAuth protocol parameters scattered across `CoreIdentClient.cs`. No constants class exists in `src/CoreIdent.Client/`. The client library has no dependency on `CoreIdent.Core` (which has `GrantTypes`, `StandardScopes`, `TokenErrors` constants classes).

### Strings to extract

| Category | Examples |
|----------|---------|
| Query params | `"client_id"`, `"redirect_uri"`, `"response_type"`, `"scope"`, `"state"`, `"nonce"`, `"code_challenge"`, `"code_challenge_method"` |
| Grant types | `"authorization_code"`, `"refresh_token"` |
| Token params | `"grant_type"`, `"code"`, `"code_verifier"`, `"token"`, `"token_type_hint"` |
| Values | `"S256"`, `"code"`, `"Bearer"` |
| DPoP | `"dpop+jwt"`, `"jwk"`, `"use_dpop_nonce"` |
| JWKS | `"kty"`, `"crv"`, `"P-256"`, `"x"`, `"y"`, `"EC"` |
| Logout | `"id_token_hint"`, `"post_logout_redirect_uri"` |

### Recommended fix

Create `src/CoreIdent.Client/OAuthConstants.cs` with nested static classes (e.g., `OAuthConstants.Parameters`, `OAuthConstants.GrantTypes`, `OAuthConstants.Values`). Low effort, no behavioral change.

---

## G. PasswordGrantHandler Default Scope Behavior (LOW)

**File:** `src/CoreIdent.Legacy.PasswordGrant/PasswordGrantHandler.cs`, lines 177-180
**Also:** `src/CoreIdent.Core/Endpoints/TokenEndpointExtensions.cs`, lines 631-638
**Category:** Security policy — permissive default

### Current behavior

Both `ValidateScopes` methods (password grant and core token endpoint) default to granting **all** of the client's `AllowedScopes` when no `scope` parameter is provided:

```csharp
requested.Count == 0
    ? allowed.ToList()   // grants everything when client sends no scope
    : requested.Where(s => allowed.Contains(s, StringComparer.Ordinal)).ToList();
```

This is **consistent** across all grant types (client_credentials, authorization_code, password, refresh_token).

### RFC position

RFC 6749 §3.3: "If the client omits the scope parameter... the authorization server MUST either process the request using a pre-defined default value or fail." Defaulting to all allowed scopes is a permissive but valid interpretation.

### Risk

A client that forgets to specify `scope` silently receives maximum access, including `offline_access` (refresh tokens) if the client allows it.

### Possible fix

Add a configurable `DefaultScopes` property to `CoreIdentClient` (defaults to `AllowedScopes` for backwards compatibility). Or add a `CoreIdentOptions.RequireExplicitScope` flag that fails requests with no scope parameter. This is a **policy decision**, not a bug.

---

## H. Recipient/Email Naming Confusion (LOW)

**File:** `src/CoreIdent.Core/Models/PasswordlessToken.cs`, lines 16-25
**Category:** Code quality — misleading property name

### Current model

```csharp
public string Email { get; set; } = string.Empty;

public string Recipient
{
    get => Email;
    set => Email = value;
}
```

`Recipient` is a computed alias that reads/writes through `Email`. Functionally correct — no runtime mismatch.

### Problem

- The `Email` property stores **phone numbers** in the SMS OTP path
- The EF schema will have a column named `Email` that contains phone numbers
- The alias adds indirection that's not obvious when reading either property in isolation

### Recommended fix

Rename `Email` to `Recipient` as the canonical backing property. Add an EF migration to rename the column. Keep `Email` as a deprecated alias during a transition period if needed. This is a **breaking schema change** for existing deployments.

---

## I. GoogleAuthProvider ID Token Not Validated (LOW-MEDIUM)

**File:** `src/CoreIdent.Providers.Google/GoogleAuthProvider.cs`, lines 96-108
**Category:** OIDC completeness

### Current behavior

`ExchangeCodeAsync` receives Google's token response (which includes `access_token`, `refresh_token`, AND `id_token`), but `GoogleTokenResponse` has no `IdToken` property — the `id_token` is silently dropped during deserialization. The handler then calls `GetUserInfoAsync` using the access token to fetch the user profile.

### Is UserInfo-only acceptable?

Yes, per OIDC Core §5.3. The UserInfo endpoint is a standards-compliant alternative to parsing the ID token. Google's UserInfo endpoint authenticates the bearer token server-side.

### What's missing

1. The `id_token` cannot be forwarded downstream (e.g., for `id_token_hint` in logout)
2. No signature validation of Google's identity assertion (relying on transport security to Google's UserInfo endpoint instead)
3. No cross-check that `sub` from UserInfo matches `sub` from ID token (OIDC §5.3.2 requirement when both are used)

### Recommended fix

1. Add `[JsonPropertyName("id_token")] public string? IdToken { get; set; }` to `GoogleTokenResponse`
2. Optionally validate the ID token signature using Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`)
3. Include the `IdToken` in `ExternalAuthResult` so downstream consumers can use it for logout or additional validation

**Effort:** Medium. Requires JWT validation logic or a dependency on `Microsoft.IdentityModel.Tokens` for Google JWKS fetching.

---

## Priority Recommendation

| Priority | Item | Effort | Reason |
|----------|------|--------|--------|
| 1 | A. Email redirect tokens | Low | One-line fragment fix closes a real token exfiltration path |
| 2 | E. ECDsa handle leak | Low | Lazy cache, non-breaking, fixes a per-request native leak |
| 3 | B. OTP verify lockout | Medium | 6-digit keyspace is brute-forceable without attempt limits |
| 4 | F. Magic strings | Low | Quick cleanup, pure refactor |
| 5 | I. Google ID token | Medium | Spec completeness, enables downstream `id_token` usage |
| 6 | H. Recipient/Email rename | Low-Med | Schema migration required |
| 7 | D. Refresh atomicity | Med-High | Interface change, low crash probability |
| 8 | G. Default scope policy | Low | Policy decision, current behavior is RFC-compliant |
| — | C. UserInfo claims | None | Already correct, just add a comment |

---

## Resolution Status (2026-03-15)

| Item | Status | Resolution |
|------|--------|------------|
| A. Email redirect tokens | **Implemented** | `TokenDeliveryMode` enum added: `QueryString` (default), `Fragment` (opt-in), `AuthorizationCode` (planned — DEVPLAN Feature 1.24). Fragment mode uses `#` delivery, not the OAuth implicit grant. |
| B. OTP verify lockout | **Implemented** | `MaxVerifyAttempts` added to `PasswordlessSmsOptions` and `PasswordlessEmailOptions` (default 5). Both InMemory and EF stores burn the token after threshold exceeded. |
| C. UserInfo claims | **Implemented** | Comment added at `UserInfoEndpointExtensions.cs:115` citing OIDC Core §5.3. No code change needed. |
| D. Refresh token atomicity | **Planned** | Added as DEVPLAN Feature 1.25 — compensating rollback or atomic exchange on `IRefreshTokenStore`. |
| E. ECDsa/RSA handle leak | **Implemented** | Both `EcdsaSigningKeyProvider` and `RsaSigningKeyProvider` now cache the public validation key in a `Lazy<>` field with disposal. |
| F. Magic strings | **Implemented** | `OAuthClientConstants.cs` added with nested `Parameters`, `GrantTypes`, `Values`, `DPoP`, `JwkParams` classes. ~30 literals replaced. |
| G. Default scope policy | **Implemented** | `DefaultScopes` property added to `CoreIdentClient` model (null = all allowed, empty = require explicit, list = those). Updated token endpoint, legacy ROPC, EF mapping, and Developer_Guide.md. |
| H. Recipient/Email rename | **Implemented** | `Email` renamed to `Recipient` across model, entity, stores, DbContext config, tests, and Technical_Plan.md. No EF migrations exist so this is a clean rename. |
| I. Google ID token | **Implemented** | `GoogleTokenResponse` now captures `id_token`. Validated against Google JWKS with issuer/audience/signature checks. Sub cross-checked per OIDC §5.3.2. `ExternalAuthResult.IdToken` surfaces the raw token for downstream use (e.g., `id_token_hint`). |
