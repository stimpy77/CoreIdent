using System.Collections.Concurrent;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IScopeStore"/> for development and testing.
/// </summary>
public sealed class InMemoryScopeStore : IScopeStore
{
    private readonly ConcurrentDictionary<string, CoreIdentScope> _scopes = new(StringComparer.OrdinalIgnoreCase);

    public InMemoryScopeStore()
    {
    }

    public InMemoryScopeStore(IEnumerable<CoreIdentScope> scopes)
    {
        SeedScopes(scopes);
    }

    /// <summary>
    /// Seeds the store with initial scopes. Useful for testing and development.
    /// </summary>
    public void SeedScopes(IEnumerable<CoreIdentScope> scopes)
    {
        foreach (var scope in scopes)
        {
            _scopes.TryAdd(scope.Name, scope);
        }
    }

    /// <summary>
    /// Seeds the store with standard OIDC scopes.
    /// </summary>
    public void SeedStandardScopes()
    {
        SeedScopes(StandardOidcScopes.All);
    }

    /// <inheritdoc />
    public Task<CoreIdentScope?> FindByNameAsync(string name, CancellationToken ct = default)
    {
        _scopes.TryGetValue(name, out var scope);
        return Task.FromResult(scope);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(IEnumerable<string> scopeNames, CancellationToken ct = default)
    {
        var result = scopeNames
            .Where(name => _scopes.ContainsKey(name))
            .Select(name => _scopes[name])
            .ToList();

        return Task.FromResult<IEnumerable<CoreIdentScope>>(result);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentScope>> GetAllAsync(CancellationToken ct = default)
    {
        return Task.FromResult<IEnumerable<CoreIdentScope>>(_scopes.Values.ToList());
    }
}

/// <summary>
/// Pre-defined standard OIDC scopes with their associated claims.
/// </summary>
public static class StandardOidcScopes
{
    public static readonly CoreIdentScope OpenId = new()
    {
        Name = StandardScopes.OpenId,
        DisplayName = "OpenID",
        Description = "Your user identifier",
        Required = true,
        Emphasize = false,
        ShowInDiscoveryDocument = true,
        UserClaims = ["sub"]
    };

    public static readonly CoreIdentScope Profile = new()
    {
        Name = StandardScopes.Profile,
        DisplayName = "Profile",
        Description = "Your profile information (name, picture, etc.)",
        Required = false,
        Emphasize = true,
        ShowInDiscoveryDocument = true,
        UserClaims = ["name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"]
    };

    public static readonly CoreIdentScope Email = new()
    {
        Name = StandardScopes.Email,
        DisplayName = "Email",
        Description = "Your email address",
        Required = false,
        Emphasize = true,
        ShowInDiscoveryDocument = true,
        UserClaims = ["email", "email_verified"]
    };

    public static readonly CoreIdentScope Address = new()
    {
        Name = StandardScopes.Address,
        DisplayName = "Address",
        Description = "Your postal address",
        Required = false,
        Emphasize = true,
        ShowInDiscoveryDocument = true,
        UserClaims = ["address"]
    };

    public static readonly CoreIdentScope Phone = new()
    {
        Name = StandardScopes.Phone,
        DisplayName = "Phone",
        Description = "Your phone number",
        Required = false,
        Emphasize = true,
        ShowInDiscoveryDocument = true,
        UserClaims = ["phone_number", "phone_number_verified"]
    };

    public static readonly CoreIdentScope OfflineAccess = new()
    {
        Name = StandardScopes.OfflineAccess,
        DisplayName = "Offline Access",
        Description = "Access to your data when you are not present",
        Required = false,
        Emphasize = true,
        ShowInDiscoveryDocument = true,
        UserClaims = []
    };

    public static readonly IReadOnlyList<CoreIdentScope> All =
    [
        OpenId,
        Profile,
        Email,
        Address,
        Phone,
        OfflineAccess
    ];
}
