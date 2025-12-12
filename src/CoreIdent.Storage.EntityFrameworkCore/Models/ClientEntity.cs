namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity for OAuth 2.0 / OIDC client applications.
/// </summary>
public class ClientEntity
{
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecretHash { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string ClientType { get; set; } = "Confidential";
    public string RedirectUrisJson { get; set; } = "[]";
    public string PostLogoutRedirectUrisJson { get; set; } = "[]";
    public string AllowedScopesJson { get; set; } = "[]";
    public string AllowedGrantTypesJson { get; set; } = "[]";
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;
    public bool RequirePkce { get; set; } = true;
    public bool AllowOfflineAccess { get; set; } = false;
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
}
