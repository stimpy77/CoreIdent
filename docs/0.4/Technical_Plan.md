# CoreIdent 0.4: Technical Plan

This document provides detailed technical specifications, architecture decisions, and implementation guidance for CoreIdent 0.4.

---

## Technology Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| **Runtime** | .NET 10 (LTS), multi-target .NET 8 | Primary: net10.0, Secondary: net8.0 |
| **Web Framework** | ASP.NET Core Minimal APIs | Endpoints via `MapCoreIdentEndpoints()` |
| **Token Format** | JWT (RFC 7519) | Access tokens, ID tokens |
| **Signing** | RS256 (default), ES256, HS256 (dev only) | Asymmetric keys for production |
| **Storage** | EF Core (pluggable), In-Memory (dev) | SQL Server, PostgreSQL, SQLite |
| **Testing** | xUnit, Shouldly, Moq | WebApplicationFactory for integration |
| **Logging** | Microsoft.Extensions.Logging | Structured logging throughout |

---

## Phase 0: Foundation Reset

### 0.1 Asymmetric Key Support

**Current State:** HS256 only (symmetric key shared between issuer and validators)

**Target State:** RS256/ES256 default with proper key management

#### Key Management Architecture

```csharp
// New abstractions
public interface ISigningKeyProvider
{
    Task<SigningCredentials> GetSigningCredentialsAsync(CancellationToken ct = default);
    Task<IEnumerable<SecurityKey>> GetValidationKeysAsync(CancellationToken ct = default);
    string Algorithm { get; } // RS256, ES256, HS256
}

public interface IKeyRotationService
{
    Task RotateKeysAsync(CancellationToken ct = default);
    Task<KeyRotationStatus> GetStatusAsync(CancellationToken ct = default);
}

// Configuration
public class CoreIdentKeyOptions
{
    public KeyType Type { get; set; } = KeyType.RSA; // RSA, ECDSA, Symmetric
    public int KeySize { get; set; } = 2048; // For RSA
    public string? KeyFilePath { get; set; } // PEM file path
    public string? KeyVaultUri { get; set; } // Azure Key Vault
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(90);
    public TimeSpan KeyOverlapPeriod { get; set; } = TimeSpan.FromDays(7);
}
```

#### Implementation Steps

1. **Create `ISigningKeyProvider` interface** in `CoreIdent.Core/Services/`
2. **Implement providers:**
   - `FileBasedKeyProvider` — Load from PEM files (dev/simple deployments)
   - `GeneratedKeyProvider` — Generate on startup, persist to configured store
   - `AzureKeyVaultProvider` — Separate package `CoreIdent.KeyManagement.AzureKeyVault`
3. **Update `JwtTokenService`** to use `ISigningKeyProvider` instead of raw key from options
4. **Update JWKS endpoint** to return multiple keys with `kid` (key ID)
5. **Deprecate `SigningKeySecret`** — Keep for backward compat, log warning if used

#### JWKS Endpoint Changes

```json
// Current (HS256 - problematic)
{
  "keys": [{
    "kty": "oct",
    "alg": "HS256",
    "k": "..." // This exposes the secret!
  }]
}

// Target (RS256)
{
  "keys": [{
    "kty": "RSA",
    "alg": "RS256",
    "kid": "key-2024-01",
    "use": "sig",
    "n": "...", // Public modulus
    "e": "AQAB" // Public exponent
  }, {
    "kty": "RSA",
    "alg": "RS256", 
    "kid": "key-2023-10", // Previous key still valid during rotation
    "use": "sig",
    "n": "...",
    "e": "AQAB"
  }]
}
```

---

### 0.2 Token Revocation (RFC 7009)

**Endpoint:** `POST /auth/revoke`

```csharp
public record TokenRevocationRequest
{
    public string Token { get; init; } = string.Empty;
    public string? TokenTypeHint { get; init; } // "access_token" or "refresh_token"
}
```

**Implementation:**
- For refresh tokens: Mark as revoked in `IRefreshTokenStore`
- For access tokens: Add to revocation list (short TTL cache matching token lifetime)
- Client authentication required for confidential clients

**Store Interface Addition:**
```csharp
public interface ITokenRevocationStore
{
    Task RevokeTokenAsync(string tokenId, DateTime expiry, CancellationToken ct = default);
    Task<bool> IsRevokedAsync(string tokenId, CancellationToken ct = default);
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
```

---

### 0.3 Token Introspection (RFC 7662)

**Endpoint:** `POST /auth/introspect`

```csharp
public record TokenIntrospectionRequest
{
    public string Token { get; init; } = string.Empty;
    public string? TokenTypeHint { get; init; }
}

public record TokenIntrospectionResponse
{
    public bool Active { get; init; }
    public string? Scope { get; init; }
    public string? ClientId { get; init; }
    public string? Username { get; init; }
    public string? TokenType { get; init; }
    public long? Exp { get; init; }
    public long? Iat { get; init; }
    public long? Nbf { get; init; }
    public string? Sub { get; init; }
    public string? Aud { get; init; }
    public string? Iss { get; init; }
    public string? Jti { get; init; }
}
```

**Implementation:**
- Validate token signature
- Check revocation status
- Check expiry
- Return claims if active

---

### 0.4 Test Infrastructure Overhaul

#### Current Problems (from codebase analysis)

1. **`AuthCodeTestWebApplicationFactory`** in `AuthorizationCodeFlowTests.cs`:
   - 200+ lines of setup code
   - Duplicates endpoint mapping from `TestHost/Program.cs`
   - Manual SQLite connection management
   - Inline seeding logic

2. **Multiple auth schemes complexity:**
   - `TestAuth` (header-based)
   - `Cookies` (cookie-based)
   - Confusion about which to use when

3. **No shared fixtures** — Each test file recreates the world

#### New Test Architecture

```
tests/
├── CoreIdent.Testing/                    # NEW: Shared test infrastructure package
│   ├── CoreIdent.Testing.csproj
│   ├── Fixtures/
│   │   ├── CoreIdentTestFixture.cs       # Base class for all tests
│   │   ├── IntegrationTestFixture.cs     # WebApplicationFactory wrapper
│   │   └── DatabaseTestFixture.cs        # EF Core test utilities
│   ├── Builders/
│   │   ├── UserBuilder.cs
│   │   ├── ClientBuilder.cs
│   │   └── ScopeBuilder.cs
│   ├── Extensions/
│   │   ├── HttpClientTestExtensions.cs
│   │   └── AssertionExtensions.cs
│   └── Seeders/
│       ├── StandardScopes.cs             # openid, profile, email, etc.
│       └── TestClients.cs                # Pre-configured test clients
├── CoreIdent.Core.Tests/                 # Unit tests (existing, refactored)
├── CoreIdent.Integration.Tests/          # Integration tests (existing, refactored)
└── CoreIdent.TestHost/                   # Minimal test host (simplified)
```

#### `CoreIdentTestFixture` Base Class

```csharp
public abstract class CoreIdentTestFixture : IAsyncLifetime
{
    protected HttpClient Client { get; private set; } = null!;
    protected IServiceProvider Services { get; private set; } = null!;
    
    private CoreIdentWebApplicationFactory _factory = null!;
    private IServiceScope _scope = null!;

    public virtual async Task InitializeAsync()
    {
        _factory = new CoreIdentWebApplicationFactory();
        ConfigureFactory(_factory);
        
        Client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        
        _scope = _factory.Services.CreateScope();
        Services = _scope.ServiceProvider;
        
        await SeedDataAsync();
    }

    protected virtual void ConfigureFactory(CoreIdentWebApplicationFactory factory) { }
    protected virtual Task SeedDataAsync() => Task.CompletedTask;

    // Helper methods
    protected async Task<CoreIdentUser> CreateUserAsync(Action<UserBuilder>? configure = null)
    {
        var builder = new UserBuilder();
        configure?.Invoke(builder);
        var user = builder.Build();
        
        var userStore = Services.GetRequiredService<IUserStore>();
        await userStore.CreateUserAsync(user, CancellationToken.None);
        return user;
    }

    protected async Task<CoreIdentClient> CreateClientAsync(Action<ClientBuilder>? configure = null)
    {
        var builder = new ClientBuilder();
        configure?.Invoke(builder);
        var client = builder.Build();
        
        var clientStore = Services.GetRequiredService<IClientStore>();
        // Store client...
        return client;
    }

    protected async Task AuthenticateAsAsync(CoreIdentUser user)
    {
        // Set up authenticated context for subsequent requests
        Client.DefaultRequestHeaders.Add("X-Test-User-Id", user.Id);
        Client.DefaultRequestHeaders.Add("X-Test-User-Email", user.UserName);
    }

    public async Task DisposeAsync()
    {
        _scope.Dispose();
        await _factory.DisposeAsync();
    }
}
```

#### `CoreIdentWebApplicationFactory`

```csharp
public class CoreIdentWebApplicationFactory : WebApplicationFactory<Program>
{
    private SqliteConnection? _connection;
    
    public Action<IServiceCollection>? ConfigureTestServices { get; set; }
    public Action<CoreIdentDbContext>? SeedDatabase { get; set; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        
        builder.ConfigureServices(services =>
        {
            // Remove existing DbContext
            services.RemoveAll<DbContextOptions<CoreIdentDbContext>>();
            services.RemoveAll<CoreIdentDbContext>();
            
            // Add SQLite in-memory
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();
            
            services.AddDbContext<CoreIdentDbContext>(options =>
                options.UseSqlite(_connection));
            
            services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();
            
            // Apply custom configuration
            ConfigureTestServices?.Invoke(services);
        });
        
        builder.Configure(app =>
        {
            // Ensure DB is created and seeded
            using var scope = app.ApplicationServices.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
            db.Database.EnsureCreated();
            
            SeedDatabase?.Invoke(db);
            SeedStandardData(db);
        });
    }

    private void SeedStandardData(CoreIdentDbContext db)
    {
        // Always seed standard OIDC scopes
        if (!db.Scopes.Any())
        {
            db.Scopes.AddRange(StandardScopes.All);
            db.SaveChanges();
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _connection?.Dispose();
    }
}
```

#### Fluent Builders

```csharp
public class UserBuilder
{
    private string _id = Guid.NewGuid().ToString();
    private string _email = $"user-{Guid.NewGuid():N}@test.com";
    private string _password = "Test123!";
    private List<Claim> _claims = new();

    public UserBuilder WithId(string id) { _id = id; return this; }
    public UserBuilder WithEmail(string email) { _email = email; return this; }
    public UserBuilder WithPassword(string password) { _password = password; return this; }
    public UserBuilder WithClaim(string type, string value) 
    { 
        _claims.Add(new Claim(type, value)); 
        return this; 
    }

    public CoreIdentUser Build() => new()
    {
        Id = _id,
        UserName = _email,
        NormalizedUserName = _email.ToUpperInvariant(),
        // Password hash handled by store
    };
    
    public string Password => _password;
}

public class ClientBuilder
{
    private string _clientId = $"client-{Guid.NewGuid():N}";
    private string? _clientSecret;
    private List<string> _grantTypes = new() { "authorization_code" };
    private List<string> _redirectUris = new() { "https://localhost/callback" };
    private List<string> _scopes = new() { "openid", "profile" };
    private bool _requirePkce = true;
    private bool _requireConsent = false;

    public ClientBuilder WithClientId(string id) { _clientId = id; return this; }
    public ClientBuilder WithSecret(string secret) { _clientSecret = secret; return this; }
    public ClientBuilder WithGrantTypes(params string[] types) { _grantTypes = types.ToList(); return this; }
    public ClientBuilder WithRedirectUris(params string[] uris) { _redirectUris = uris.ToList(); return this; }
    public ClientBuilder WithScopes(params string[] scopes) { _scopes = scopes.ToList(); return this; }
    public ClientBuilder RequireConsent(bool require = true) { _requireConsent = require; return this; }
    public ClientBuilder AsPublicClient() { _clientSecret = null; _requirePkce = true; return this; }
    public ClientBuilder AsConfidentialClient(string secret) { _clientSecret = secret; return this; }

    public CoreIdentClient Build() => new()
    {
        ClientId = _clientId,
        ClientSecrets = _clientSecret != null 
            ? new List<CoreIdentClientSecret> { new() { Value = _clientSecret } } 
            : new(),
        AllowedGrantTypes = _grantTypes,
        RedirectUris = _redirectUris,
        AllowedScopes = _scopes,
        RequirePkce = _requirePkce,
        RequireConsent = _requireConsent
    };
}
```

#### Assertion Extensions

```csharp
public static class JwtAssertionExtensions
{
    public static JwtSecurityToken ShouldBeValidJwt(this string token, SecurityKey? validationKey = null)
    {
        token.ShouldNotBeNullOrWhiteSpace();
        
        var handler = new JwtSecurityTokenHandler();
        handler.CanReadToken(token).ShouldBeTrue("Token should be a valid JWT format");
        
        var jwt = handler.ReadJwtToken(token);
        jwt.ShouldNotBeNull();
        
        return jwt;
    }

    public static JwtSecurityToken ShouldHaveClaim(this JwtSecurityToken token, string type, string? value = null)
    {
        var claim = token.Claims.FirstOrDefault(c => c.Type == type);
        claim.ShouldNotBeNull($"Token should have claim '{type}'");
        
        if (value != null)
        {
            claim.Value.ShouldBe(value, $"Claim '{type}' should have value '{value}'");
        }
        
        return token;
    }

    public static JwtSecurityToken ShouldNotHaveClaim(this JwtSecurityToken token, string type)
    {
        var claim = token.Claims.FirstOrDefault(c => c.Type == type);
        claim.ShouldBeNull($"Token should not have claim '{type}'");
        return token;
    }

    public static JwtSecurityToken ShouldExpireAfter(this JwtSecurityToken token, TimeSpan duration)
    {
        var expectedExpiry = DateTime.UtcNow.Add(duration);
        token.ValidTo.ShouldBeGreaterThan(expectedExpiry.Subtract(TimeSpan.FromSeconds(30)));
        return token;
    }
}

public static class HttpResponseAssertionExtensions
{
    public static async Task<T> ShouldBeSuccessfulWithContent<T>(this HttpResponseMessage response)
    {
        response.IsSuccessStatusCode.ShouldBeTrue(
            $"Expected success but got {response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        
        var content = await response.Content.ReadFromJsonAsync<T>();
        content.ShouldNotBeNull();
        return content;
    }

    public static async Task ShouldBeUnauthorized(this HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    public static async Task ShouldBeBadRequest(this HttpResponseMessage response, string? containsError = null)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        
        if (containsError != null)
        {
            var content = await response.Content.ReadAsStringAsync();
            content.ShouldContain(containsError);
        }
    }
}
```

---

## Phase 1: Passwordless & Developer Experience

### 1.1 Email Magic Link Authentication

#### Flow

```
1. User enters email → POST /auth/passwordless/email/start
2. Server generates token, stores it, sends email
3. User clicks link → GET /auth/passwordless/email/verify?token=xxx
4. Server validates token, issues session/tokens
```

#### Abstractions

```csharp
public interface IEmailSender
{
    Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct = default);
}

public interface IPasswordlessTokenStore
{
    Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default);
    Task<PasswordlessToken?> GetAndConsumeTokenAsync(string token, CancellationToken ct = default);
    Task CleanupExpiredAsync(CancellationToken ct = default);
}

public record PasswordlessToken
{
    public string Id { get; init; } = Guid.NewGuid().ToString();
    public string Email { get; init; } = string.Empty;
    public string TokenHash { get; init; } = string.Empty; // Store hashed
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; init; }
    public bool Consumed { get; init; }
    public string? UserId { get; init; } // If linking to existing user
}
```

#### Configuration

```csharp
public class PasswordlessEmailOptions
{
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    public int MaxAttemptsPerHour { get; set; } = 5; // Rate limiting
    public string EmailSubject { get; set; } = "Sign in to {AppName}";
    public string? EmailTemplatePath { get; set; } // Custom template
    public string LinkBaseUrl { get; set; } = string.Empty; // Required
}
```

#### Endpoints

```csharp
// POST /auth/passwordless/email/start
public record PasswordlessEmailStartRequest
{
    public string Email { get; init; } = string.Empty;
}

public record PasswordlessEmailStartResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = "If the email exists, a login link has been sent.";
}

// GET /auth/passwordless/email/verify?token=xxx
// Returns: Redirect to configured success URL with tokens, or error page
```

---

### 1.2 Passkey Integration

Wrap .NET 10's built-in `IdentityPasskeyOptions` with CoreIdent's simplified configuration:

```csharp
public class CoreIdentPasskeyOptions
{
    public string? RelyingPartyId { get; set; } // Domain, e.g., "example.com"
    public string RelyingPartyName { get; set; } = "CoreIdent";
    public TimeSpan ChallengeTimeout { get; set; } = TimeSpan.FromMinutes(5);
    public AuthenticatorAttachment? PreferredAttachment { get; set; } // platform, cross-platform
    public UserVerificationRequirement UserVerification { get; set; } = UserVerificationRequirement.Preferred;
}

// Extension method
public static IServiceCollection AddCoreIdentPasskeys(
    this IServiceCollection services, 
    Action<CoreIdentPasskeyOptions>? configure = null)
{
    var options = new CoreIdentPasskeyOptions();
    configure?.Invoke(options);
    
    // Map to .NET 10's IdentityPasskeyOptions
    services.Configure<IdentityPasskeyOptions>(identityOptions =>
    {
        identityOptions.ServerDomain = options.RelyingPartyId;
        identityOptions.AuthenticatorTimeout = options.ChallengeTimeout;
        // ... other mappings
    });
    
    return services;
}
```

---

### 1.3 ClaimsPrincipal Extensions (C# 14)

```csharp
// CoreIdent.Core/Extensions/ClaimsPrincipalExtensions.cs
using System.Security.Claims;

public static class ClaimsPrincipalExtensions
{
    extension(ClaimsPrincipal principal)
    {
        public string? Email => principal.FindFirstValue(ClaimTypes.Email) 
                             ?? principal.FindFirstValue("email");
        
        public string? UserId => principal.FindFirstValue(ClaimTypes.NameIdentifier)
                              ?? principal.FindFirstValue("sub");
        
        public string? Name => principal.FindFirstValue(ClaimTypes.Name)
                            ?? principal.FindFirstValue("name");
        
        public Guid GetUserIdAsGuid()
        {
            var id = UserId;
            if (string.IsNullOrEmpty(id) || !Guid.TryParse(id, out var guid))
                throw new InvalidOperationException("User ID is not a valid GUID");
            return guid;
        }
        
        public T? GetClaim<T>(string claimType) where T : IParsable<T>
        {
            var value = principal.FindFirstValue(claimType);
            if (string.IsNullOrEmpty(value))
                return default;
            return T.Parse(value, null);
        }
        
        public IEnumerable<string> GetRoles() => principal.Claims
            .Where(c => c.Type == ClaimTypes.Role || c.Type == "role")
            .Select(c => c.Value);
        
        public bool IsInRole(string role) => GetRoles().Contains(role, StringComparer.OrdinalIgnoreCase);
    }
}
```

---

### 1.4 `dotnet new` Templates

#### Template: `coreident-api`

```
templates/
└── coreident-api/
    ├── .template.config/
    │   └── template.json
    ├── Program.cs
    ├── appsettings.json
    └── CoreIdentApi.csproj
```

**template.json:**
```json
{
  "$schema": "http://json.schemastore.org/template",
  "author": "CoreIdent Contributors",
  "classifications": ["Web", "API", "Authentication"],
  "identity": "CoreIdent.Templates.Api",
  "name": "CoreIdent API",
  "shortName": "coreident-api",
  "tags": {
    "language": "C#",
    "type": "project"
  },
  "sourceName": "CoreIdentApi",
  "symbols": {
    "usePasswordless": {
      "type": "parameter",
      "datatype": "bool",
      "defaultValue": "true",
      "description": "Include passwordless email authentication"
    },
    "useEfCore": {
      "type": "parameter",
      "datatype": "bool", 
      "defaultValue": "true",
      "description": "Use Entity Framework Core for storage"
    }
  }
}
```

**Program.cs template:**
```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCoreIdent(options =>
{
    options.Issuer = builder.Configuration["CoreIdent:Issuer"]!;
    options.Audience = builder.Configuration["CoreIdent:Audience"]!;
})
#if (usePasswordless)
.AddPasswordlessEmail(email =>
{
    email.LinkBaseUrl = builder.Configuration["CoreIdent:BaseUrl"]!;
})
#endif
#if (useEfCore)
.AddEntityFrameworkStores<AppDbContext>()
#endif
;

#if (useEfCore)
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));
#endif

var app = builder.Build();

app.MapCoreIdentEndpoints();
app.MapGet("/", () => "CoreIdent API is running");

app.Run();
```

---

## Patterns to Preserve from Existing Implementation

### Good Patterns (Keep)

1. **Interface-driven design** — `IUserStore`, `ITokenService`, `IClientStore`, etc.
2. **`TryAdd` for DI registration** — Allows consumers to override
3. **Options validation** — `IValidateOptions<CoreIdentOptions>`
4. **Token family tracking** — For refresh token theft detection
5. **Hashed token storage** — Never store raw refresh tokens
6. **Shouldly assertions** — Readable test assertions
7. **Moq for unit tests** — Clean dependency mocking

### Patterns to Improve

1. **Endpoint organization** — Current extension methods are large; split by feature
2. **Error responses** — Standardize on RFC 7807 Problem Details
3. **Logging** — Add structured logging with correlation IDs
4. **Configuration** — Support both fluent API and `appsettings.json`

---

## Breaking Changes from 0.3.x

| Change | Migration Path |
|--------|----------------|
| `SigningKeySecret` deprecated | Use `AddSigningKey()` with RSA/ECDSA |
| HS256 not default | Explicitly opt-in with `UseSymmetricKey()` for dev |
| `IRefreshTokenStore` changes | Add `RevokeByFamilyAsync()` method |
| Test infrastructure | Use new `CoreIdentTestFixture` base class |
| Namespace changes | Update `using` statements |

---

## File Structure (Target)

```
src/
├── CoreIdent.Core/
│   ├── Configuration/
│   │   ├── CoreIdentOptions.cs
│   │   ├── CoreIdentKeyOptions.cs
│   │   └── PasswordlessOptions.cs
│   ├── Endpoints/
│   │   ├── AuthEndpoints.cs
│   │   ├── TokenEndpoints.cs
│   │   ├── PasswordlessEndpoints.cs
│   │   ├── DiscoveryEndpoints.cs
│   │   └── OAuthEndpoints.cs
│   ├── Services/
│   │   ├── ITokenService.cs
│   │   ├── JwtTokenService.cs
│   │   ├── ISigningKeyProvider.cs
│   │   ├── RsaSigningKeyProvider.cs
│   │   ├── IPasswordlessService.cs
│   │   └── PasswordlessService.cs
│   ├── Stores/
│   │   ├── IUserStore.cs
│   │   ├── IRefreshTokenStore.cs
│   │   ├── ITokenRevocationStore.cs
│   │   ├── IPasswordlessTokenStore.cs
│   │   └── InMemory/
│   └── Extensions/
│       ├── ServiceCollectionExtensions.cs
│       ├── EndpointRouteBuilderExtensions.cs
│       └── ClaimsPrincipalExtensions.cs
├── CoreIdent.Storage.EntityFrameworkCore/
├── CoreIdent.Providers.Google/
├── CoreIdent.Providers.Microsoft/
├── CoreIdent.Testing/
└── CoreIdent.Templates/
```

---

## Implementation Priority

### Week 1-2: Phase 0 Foundation
- [ ] Asymmetric key infrastructure
- [ ] Update JWKS endpoint
- [ ] Token revocation endpoint
- [ ] Token introspection endpoint

### Week 3-4: Test Infrastructure
- [ ] Create `CoreIdent.Testing` package
- [ ] Implement fixtures and builders
- [ ] Refactor existing tests to use new infrastructure
- [ ] Ensure all existing tests pass

### Week 5-6: Passwordless
- [ ] Email magic link flow
- [ ] Passkey wrapper
- [ ] SMS abstraction (interface only)

### Week 7-8: Developer Experience
- [ ] `dotnet new` templates
- [ ] ClaimsPrincipal extensions
- [ ] Documentation site setup
- [ ] Migration guide from 0.3.x

---

## Open Questions

1. **Key storage for generated keys** — File system? Database? Require external (Key Vault)?
2. **Multi-tenancy** — Should CoreIdent support multiple issuers in one instance?
3. **Blazor-specific support** — Dedicated package or examples only?
4. **Rate limiting** — Built-in or defer to middleware (e.g., `AspNetCoreRateLimit`)?

---

## References

- [RFC 7009 - Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [.NET 10 Passkey Support](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys)
- [C# 14 Extension Members](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/extension-methods)
