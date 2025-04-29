# Endpoint Refactoring Plan (Unified)

This plan consolidates the three previous LLM proposals—`EndpointRefactoringPlan.gemini-25-pro.md`, `EndpointRefactoringPlan.o4-mini-high.md`, and `EndpointRefactoringPlan.claude37sonnet-thinking.md`—together with an **independent architectural review**.  
The result is a single, authoritative blueprint for breaking up the monolithic `CoreIdentEndpointRouteBuilderExtensions.cs` file into focused, easily-maintainable extension classes while updating project documentation.

---

## 0. Guiding Principles

1. **Single Responsibility Principle (SRP)** – each new extension file should own one clear functional area.
2. **Public API Clarity** – every area exposes **one** entry method (e.g. `MapAuthEndpoints`) that internally wires multiple concrete endpoints. This keeps the public surface small while still encouraging cohesion.
3. **Minimal Breaking Change** – the external contract (`MapCoreIdentEndpoints(...)`) remains intact; only internal structure changes.
4. **Documentation as Source of Truth** – `LLMINDEX.md` must always reflect the project layout **immediately** after each structural change.
5. **Compile-time Safety First** – all refactors must complete with a clean `dotnet build`.

---

## 1. High-Level File Breakdown

| New File | Namespace | Entry Method | Primary Endpoints Migrated | **Source Line Range** |
|----------|-----------|--------------|----------------------------|-----------------------|
| `AuthEndpointsExtensions.cs` | `CoreIdent.Core.Extensions` | `MapAuthEndpoints(...)` | `/register`, `/login` | `/register`: **59-131**  \\ `/login`: **134-279** |
| `OAuthEndpointsExtensions.cs` | `CoreIdent.Core.Extensions` | `MapOAuthEndpoints(...)` | `/authorize`, `/consent` (`GET` & `POST`) | `/authorize`: **285-579**  \\ `/consent (GET)`: **603-633**  \\ `/consent (POST)`: **639-770** |
| `TokenEndpointsExtensions.cs` | `CoreIdent.Core.Extensions` | `MapTokenEndpoints(...)` | `/token` (all grant types) | **762-1280** |
| `DiscoveryEndpointsExtensions.cs` | `CoreIdent.Core.Extensions` | `MapDiscoveryEndpoints(...)` | `/.well-known/openid-configuration`, `/.well-known/jwks.json` | `openid-configuration`: **1283-1320**  \\ `jwks.json`: **1323-1360** |
| **(Relocated)** `InMemoryAuthorizationCodeStore.cs` | `CoreIdent.Core.Stores.InMemory` | — | — | **1372-1428** |

> **Why this exact split?**  
> • *Gemini* grouped Token under OAuth, *o4-mini* split Token separately, *Claude* kept OAuth & Token distinct but placed Consent with OAuth. Splitting **Tokens** into its own file yields the clearest cohesion: token lifecycle operations are orthogonal to the user-interactive OAuth flow.  
> • The discovery endpoints are HTTP-root scoped and belong in their own file as proposed by all three earlier plans.  
> • My independent review favors single public entry methods (Gemini & Claude) over many granular ones (o4-mini) to reduce surface area.

---

## 2. Detailed Responsibilities

### 2.1 `AuthEndpointsExtensions.cs`
* **Location:** `src/CoreIdent.Core/Extensions/AuthEndpointsExtensions.cs`
* **Endpoints:**
  * `POST {BasePath}{RegisterPath}` – *User Registration*  (≈ lines 42-128 of source)
  * `POST {BasePath}{LoginPath}` – *User Login*           (≈ lines 130-284)
* **Shared Logic:** model validation, result handling, common logging.

### 2.2 `OAuthEndpointsExtensions.cs`
* **Location:** `src/CoreIdent.Core/Extensions/OAuthEndpointsExtensions.cs`
* **Endpoints:**
  * `GET  {BasePath}{AuthorizePath}` – *OAuth2 / OIDC Authorize* (≈ lines 286-562)
  * `GET  {BasePath}{ConsentPath}`   – *Consent Page*            (≈ lines 564-647)
  * `POST {BasePath}{ConsentPath}`   – *Consent Submit*          (≈ lines 649-756)
* **Notes:** Keeps interactive, browser-facing endpoints together.

### 2.3 `TokenEndpointsExtensions.cs`
* **Location:** `src/CoreIdent.Core/Extensions/TokenEndpointsExtensions.cs`
* **Endpoints:**
  * `POST {BasePath}{TokenPath}`          – *Token Issuance* (`authorization_code`, `refresh_token`, `client_credentials`)  (≈ lines 758-1192)
  * *Optional* – Include `/refresh`, `/revoke`, `/introspect` if/when implemented (o4-mini suggestion).
* **Rationale:** Token management often evolves (rotation, revocation, introspection); isolating here simplifies future work.

### 2.4 `DiscoveryEndpointsExtensions.cs`
* **Location:** `src/CoreIdent.Core/Extensions/DiscoveryEndpointsExtensions.cs`
* **Endpoints (root-mapped):**
  * `GET /.well-known/openid-configuration` – OIDC discovery  (≈ lines 1194-1230)
  * `GET /.well-known/jwks.json`            – JWKS keys       (≈ lines 1232-1268)

### 2.5 Store Relocation
* **Source Lines:** 1274-1341 of `CoreIdentEndpointRouteBuilderExtensions.cs`
* **Destination:** `src/CoreIdent.Core/Stores/InMemory/InMemoryAuthorizationCodeStore.cs`
* **Namespace:** `CoreIdent.Core.Stores.InMemory`

---

## 3. Coordinator Update

`CoreIdentEndpointRouteBuilderExtensions.cs` becomes a thin façade:

```csharp
public static class CoreIdentEndpointRouteBuilderExtensions
{
    public static RouteGroupBuilder MapCoreIdentEndpoints(
        this IEndpointRouteBuilder endpoints,
        Action<CoreIdentRouteOptions>? configureRoutes = null)
    {
        var opts = new CoreIdentRouteOptions();
        configureRoutes?.Invoke(opts);

        var group = endpoints.MapGroup(opts.BasePath);
        group.MapAuthEndpoints(opts);
        group.MapOAuthEndpoints(opts);
        group.MapTokenEndpoints(opts);
        endpoints.MapDiscoveryEndpoints(opts);
        return group;
    }
}
```

Optionally, mark the old method bodies **`Obsolete`** while refactors are in flight.

---

## 4. Implementation Checklist

1. **Cut & Paste** code blocks into new files; maintain original logic.
2. **Adjust Namespaces / Usings** to align with new file paths.
3. Remove relocated lines from the original monolith; leave only the coordinator.
4. **Update `LLMINDEX.md`** – remove monolithic entries, add all new files with short descriptions.
5. `dotnet build` – iterate until compilation is green.
6. Commit with message `refactor: split CoreIdentEndpointRouteBuilderExtensions into focused extension files`.

---

## 5. Post-Refactor Benefits

* **Maintainability:** Smaller files with narrow responsibility improve readability.
* **Discoverability:** Developers can jump directly to the feature group instead of scrolling a 1,300-line file.
* **Extensibility:** New flows (Device Code, PAR, Revocation) can be added by creating additional extension files without touching unrelated code.
* **Easier Testing:** Each functional area can be integration tested in isolation.

---

### Appendix A – Future Considerations
* **UserProfileEndpointsExtensions.cs** – For `/me` style endpoints once implemented (per o4-mini).
* **MFAEndpointsExtensions.cs** – Will slot naturally beside existing files when MFA lands (Phase 4).
* **Versioned API Namespaces** – If multiple API versions are planned, consider `Extensions.V1` sub-namespaces.


### Appendix B – Endpoint-to-Line Mapping (Full Detail)

| Endpoint | HTTP Verb | Line Range | Notes |
|----------|-----------|-----------|-------|
| `/register` | POST | **59-131** | Registers a new user. |
| `/login` | POST | **134-279** | User login & JWT issuance. |
| `/authorize` | GET | **285-579** | OAuth2 Authorization Code flow start (includes consent checks & redirect).
| `/consent` | GET | **603-633** | Renders minimal consent form (HTML). |
| `/consent` | POST | **639-770** | Handles consent submission & UserGrant storage. |
| `/token` | POST | **762-1280** | Handles `authorization_code`, `refresh_token`, `client_credentials` grants. |
| `/.well-known/openid-configuration` | GET | **1283-1320** | Publishes OIDC discovery metadata. |
| `/.well-known/jwks.json` | GET | **1323-1360** | Publishes JWKS. |
| *(Store)* `InMemoryAuthorizationCodeStore` | — | **1372-1428** | In-memory implementation of `IAuthorizationCodeStore`. |

---

*Last updated by unified plan generator.* 