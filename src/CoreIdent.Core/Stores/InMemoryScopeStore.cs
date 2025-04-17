using CoreIdent.Core.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Simple in-memory store for OAuth scopes.
/// </summary>
public class InMemoryScopeStore : IScopeStore
{
    private readonly ConcurrentDictionary<string, CoreIdentScope> _scopes = new(StringComparer.Ordinal);
    private readonly ILogger<InMemoryScopeStore> _logger;

    // Standard OIDC scopes
    public static IEnumerable<CoreIdentScope> GetStandardOidcScopes() => new List<CoreIdentScope>
    {
        new CoreIdentScope
        {
            Name = "openid",
            DisplayName = "Your user identifier",
            Description = "Access to your unique user ID.",
            Required = true // OpenID Connect requires the 'openid' scope.
        },
        new CoreIdentScope
        {
            Name = "profile",
            DisplayName = "User profile",
            Description = "Your user profile information (first name, last name, etc.)",
            Emphasize = true,
            UserClaims = new List<CoreIdentScopeClaim> // Example standard claims
            {
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.Name },
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.FamilyName },
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.GivenName },
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.MiddleName },
                new CoreIdentScopeClaim { Type = "nickname" },
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.PreferredUsername },
                new CoreIdentScopeClaim { Type = "profile" },
                new CoreIdentScopeClaim { Type = "picture" },
                new CoreIdentScopeClaim { Type = "website" },
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.Gender },
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.Birthdate },
                new CoreIdentScopeClaim { Type = "zoneinfo" },
                new CoreIdentScopeClaim { Type = "locale" },
                new CoreIdentScopeClaim { Type = "updated_at" },
            }
        },
        new CoreIdentScope
        {
            Name = "email",
            DisplayName = "Your email address",
            Description = "Access to your email address.",
            Emphasize = true,
             UserClaims = new List<CoreIdentScopeClaim>
            {
                new CoreIdentScopeClaim { Type = JwtRegisteredClaimNames.Email },
                new CoreIdentScopeClaim { Type = "email_verified" },
            }
        },
         new CoreIdentScope
        {
            Name = "address",
            DisplayName = "Your postal address",
            Description = "Access to your postal address.",
            Emphasize = true,
             UserClaims = new List<CoreIdentScopeClaim>
            {
                new CoreIdentScopeClaim { Type = "address" },
            }
        },
         new CoreIdentScope
        {
            Name = "phone",
            DisplayName = "Your phone number",
            Description = "Access to your phone number.",
            Emphasize = true,
             UserClaims = new List<CoreIdentScopeClaim>
            {
                new CoreIdentScopeClaim { Type = "phone_number" },
                new CoreIdentScopeClaim { Type = "phone_number_verified" },
            }
        },
        new CoreIdentScope
        {
            Name = "offline_access",
            DisplayName = "Offline access",
            Description = "Access to your resources when you are not online.",
            Emphasize = true
            // No specific user claims, enables refresh tokens.
        }
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryScopeStore"/> class.
    /// Seeds standard OIDC scopes and optionally additional scopes.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="additionalScopes">Optional list of additional scopes to seed.</param>
    public InMemoryScopeStore(ILogger<InMemoryScopeStore> logger, IEnumerable<CoreIdentScope>? additionalScopes = null)
    {
        _logger = logger;
        var initialScopes = GetStandardOidcScopes().ToList();
        if (additionalScopes != null)
        {
            initialScopes.AddRange(additionalScopes);
        }

        foreach (var scope in initialScopes)
        {
            if (!_scopes.TryAdd(scope.Name, scope))
            {
                _logger.LogWarning("Failed to add initial scope with duplicate name: {ScopeName}", scope.Name);
            }
            else
            {
                _logger.LogDebug("Added initial scope: {ScopeName}", scope.Name);
            }
        }
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scopeNames);
        cancellationToken.ThrowIfCancellationRequested();

        var foundScopes = new List<CoreIdentScope>();
        foreach (var name in scopeNames.Distinct()) // Ensure distinct names
        {
            if (_scopes.TryGetValue(name, out var scope) && scope.Enabled)
            {
                foundScopes.Add(scope);
                 _logger.LogDebug("Found enabled scope: {ScopeName}", name);
            }
            else
            {
                 _logger.LogDebug("Scope not found or disabled: {ScopeName}", name);
            }
        }

        // Return copies? For simplicity, returning direct references.
        return Task.FromResult<IEnumerable<CoreIdentScope>>(foundScopes);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentScope>> GetAllScopesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var allEnabledScopes = _scopes.Values.Where(s => s.Enabled).ToList();
         _logger.LogDebug("Retrieving all {Count} enabled scopes.", allEnabledScopes.Count);
        // Return copies? For simplicity, returning direct references.
        return Task.FromResult<IEnumerable<CoreIdentScope>>(allEnabledScopes);
    }

     // Optional: Add methods for managing scopes if needed (e.g., AddScopeAsync, UpdateScopeAsync)
} 