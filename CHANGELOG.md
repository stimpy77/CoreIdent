# Changelog

## 1.0.0

### Added
- OAuth/OIDC server primitives on .NET 10 (net10.0)
- Asymmetric signing by default (RS256/ES256) with JWKS publishing (public keys only)
- Token lifecycle endpoints: token issuance, revocation (RFC 7009), introspection (RFC 7662)
- Authorization Code + PKCE with consent flow
- Passwordless authentication: email magic links, passkeys/WebAuthn, SMS OTP
- Pluggable stores (in-memory defaults + EF Core implementations)
- CLI tool: `dotnet coreident`
- Optional metrics instrumentation via `System.Diagnostics.Metrics`
- `dotnet new` templates (`CoreIdent.Templates`)

### Changed
- Documentation paths moved from `docs/` versioned folder to `docs/`

### Notes
- See documentation in `docs/` for current guidance.
