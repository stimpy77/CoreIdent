# Migration Guide

This document captures high-level upgrade notes for users integrating CoreIdent into an existing application.

## Upgrading to 1.0.0

### Requirements
- .NET 10 SDK

### Notes
- CoreIdent 1.0.0 is not intended to be a drop-in replacement for older codebases; treat upgrades as a re-integration.
- **Asymmetric signing is the default** (RS256/ES256). Symmetric signing (HS256) is supported for development/testing only.
- **Configuration and extension methods changed**: host integration is via `AddCoreIdent(...)` and `MapCoreIdentEndpoints()`.
- **Stores and models have changed**: update any custom store implementations to match the current `CoreIdent.Core` store interfaces.

### Recommended upgrade approach
- Treat the upgrade as a re-integration:
  - Stand up a new 1.0.0 host
  - Reconfigure issuer/audience and signing keys
  - Recreate clients/scopes in the new storage model
  - Re-test OAuth/OIDC flows end-to-end
