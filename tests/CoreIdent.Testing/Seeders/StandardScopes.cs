using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Storage.EntityFrameworkCore.Models;

namespace CoreIdent.Testing.Seeders;

public static class StandardScopes
{
    public static readonly IReadOnlyList<ScopeEntity> All =
    [
        new ScopeEntity
        {
            Name = CoreIdent.Core.Models.StandardScopes.OpenId,
            DisplayName = "OpenID",
            Description = "Your user identifier",
            Required = true,
            Emphasize = false,
            ShowInDiscoveryDocument = true,
            UserClaimsJson = JsonSerializer.Serialize(new[] { "sub" })
        },
        new ScopeEntity
        {
            Name = CoreIdent.Core.Models.StandardScopes.Profile,
            DisplayName = "Profile",
            Description = "Your profile information",
            Required = false,
            Emphasize = true,
            ShowInDiscoveryDocument = true,
            UserClaimsJson = JsonSerializer.Serialize(new[] { "name" })
        },
        new ScopeEntity
        {
            Name = CoreIdent.Core.Models.StandardScopes.Email,
            DisplayName = "Email",
            Description = "Your email address",
            Required = false,
            Emphasize = true,
            ShowInDiscoveryDocument = true,
            UserClaimsJson = JsonSerializer.Serialize(new[] { "email", "email_verified" })
        },
        new ScopeEntity
        {
            Name = CoreIdent.Core.Models.StandardScopes.OfflineAccess,
            DisplayName = "Offline Access",
            Description = "Access when you are not present",
            Required = false,
            Emphasize = true,
            ShowInDiscoveryDocument = true,
            UserClaimsJson = JsonSerializer.Serialize(Array.Empty<string>())
        }
    ];
}
