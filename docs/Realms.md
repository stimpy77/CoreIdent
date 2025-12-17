# Realms

This document describes the **realms foundation** in CoreIdent.

A *realm* is a logical partition within a single CoreIdent host that can have different:

- Issuer / audience
- Signing keys
- Clients, scopes, and tokens
- Users and grants

The goal is to make CoreIdent a flexible base for future add-ons (for example: multi-tenancy, per-tenant branding, SAML/LDAP integration in a separate package) **without changing behavior for single-realm apps**.

---

## Why realms exist

Many deployments need more than a single global identity configuration:

- Multiple customer tenants hosted in one app instance
- Multiple issuers (per tenant or per environment)
- Key isolation (per tenant keys, key rotation policies)
- Storage isolation (different databases per tenant)

CoreIdent’s realms foundation is designed to:

- Keep the default experience simple (single realm)
- Add extension points for multi-realm hosts
- Avoid forcing multi-tenancy semantics into apps that do not need them

---

## Design principles

- **Single-realm is the default.** If you do not register any realm services, CoreIdent uses a default realm id and behaves like a single-tenant system.
- **Realm support is additive.** Realm-aware interfaces exist alongside existing single-realm interfaces.
- **Host decides how to resolve the realm.** CoreIdent does not impose a specific multi-tenancy model.
- **Override via DI.** Default implementations use `TryAdd*` so you can replace them.

---

## Key concepts

### Realm id

A realm is identified by a string `realmId`.

CoreIdent uses a conventional default value:

- `"default"`

### Realm resolver and context

CoreIdent separates *how a realm id is chosen* from *how code consumes it*:

- `ICoreIdentRealmResolver`
  - Responsible for resolving the realm id for the current request.
  - Typical strategies include:
    - A request header (for example `X-Realm`)
    - A host name mapping (for example `tenant-a.example.com`)
    - A route prefix (for example `/t/{realm}/auth/...`)
- `ICoreIdentRealmContext`
  - Provides the current request’s `RealmId`.
  - The default implementation reads from `HttpContext`.

### Realm-aware issuer and audience

CoreIdent introduces:

- `ICoreIdentIssuerAudienceProvider`

This is the API endpoints and token validation logic should use when they need issuer/audience.

Default behavior:

- Returns the configured `CoreIdentOptions.Issuer` and `CoreIdentOptions.Audience` for the current realm.
- For single-realm apps, this is effectively the same as reading `CoreIdentOptions` directly.

### Realm-aware signing keys

CoreIdent introduces:

- `IRealmSigningKeyProviderResolver`

This is used to select an `ISigningKeyProvider` based on `realmId`.

Default behavior:

- Returns the single configured `ISigningKeyProvider` for every realm.

If you want per-realm keys, replace the resolver with an implementation that selects keys from:

- A database
- Azure Key Vault / AWS KMS
- Per-tenant certificate stores

---

## Realm-aware store interfaces

CoreIdent keeps existing store interfaces (for example `IUserStore`) for single-realm usage.

For realm-ready implementations, CoreIdent also provides realm-aware store interfaces that accept a `realmId`, for example:

- `IRealmClientStore`
- `IRealmScopeStore`
- `IRealmAuthorizationCodeStore`
- `IRealmRefreshTokenStore`
- `IRealmTokenRevocationStore`
- `IRealmUserGrantStore`
- `IRealmUserStore`
- `IRealmPasswordlessTokenStore`

### Default adapters

To preserve backwards compatibility, CoreIdent ships default adapters:

- If you only register the existing single-realm stores, CoreIdent can still resolve and call the realm-aware interfaces.
- The default adapters ignore `realmId` and delegate to the existing store.

This means:

- Existing hosts do not need to change store implementations.
- Multi-realm hosts can progressively replace only the pieces they need.

---

## How endpoints use realms

Endpoints and token validation now follow this pattern:

- Resolve `realmId` from `ICoreIdentRealmContext`
- Use realm-aware services to select:
  - Issuer/audience (`ICoreIdentIssuerAudienceProvider`)
  - Signing keys (`IRealmSigningKeyProviderResolver`)
- Use realm-aware stores to read/write data for that realm

The result is that the *shape* of the system is realm-ready even if the host uses the same configuration for all realms.

---

## How to enable realms in a host

### Single-realm (default)

You do not need to do anything special.

- `realmId` resolves to `"default"`
- Issuer/audience come from `CoreIdentOptions`
- Signing keys use the configured `ISigningKeyProvider`
- Stores behave as they always have

### Multi-realm host

Register your own realm resolver:

- Implement `ICoreIdentRealmResolver`
- Ensure the resolved realm id is stable and validated

Then optionally replace any of:

- `IRealmIssuerAudienceProvider` / `ICoreIdentIssuerAudienceProvider`
- `IRealmSigningKeyProviderResolver`
- Any realm-aware stores

A typical deployment progression:

1. Add realm resolution (header/host/path)
2. Add per-realm issuer/audience
3. Add per-realm signing keys
4. Add per-realm storage

---

## Extension scenarios

### Per-tenant issuer/audience

Replace issuer/audience providers so that `issuer` and `audience` are computed per realm. Common approaches:

- Store per-tenant issuer/audience in a database
- Derive issuer from the request host name

### Per-tenant keys

Replace `IRealmSigningKeyProviderResolver` so that tokens are signed per realm and JWKS exposes realm-appropriate public keys.

### Per-tenant storage

Replace realm-aware stores with implementations that isolate data per realm.

Isolation approaches:

- Shared database with `RealmId` column on all relevant rows
- Separate schema per tenant
- Separate database per tenant

CoreIdent intentionally does not mandate which approach you use.

---

## Notes on backwards compatibility

The realms foundation is intended to be safe for existing hosts:

- Defaults preserve single-realm behavior.
- Realm-aware services/stores have default implementations that delegate to existing single-realm services/stores.
- You can adopt realms incrementally by overriding only the specific pieces your deployment needs.
