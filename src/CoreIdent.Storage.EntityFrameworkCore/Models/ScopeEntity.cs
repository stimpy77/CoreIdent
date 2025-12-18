namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity for storing scope definitions.
/// </summary>
public class ScopeEntity
{
    /// <summary>
    /// Gets or sets the scope name (unique key).
    /// </summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the display name for the scope.
    /// </summary>
    public string? DisplayName { get; set; }
    /// <summary>
    /// Gets or sets the scope description.
    /// </summary>
    public string? Description { get; set; }
    /// <summary>
    /// Gets or sets a value indicating whether consent is required for this scope.
    /// </summary>
    public bool Required { get; set; }
    /// <summary>
    /// Gets or sets a value indicating whether this scope should be emphasized in UI.
    /// </summary>
    public bool Emphasize { get; set; }
    /// <summary>
    /// Gets or sets a value indicating whether this scope is included in the discovery document.
    /// </summary>
    public bool ShowInDiscoveryDocument { get; set; } = true;
    /// <summary>
    /// Gets or sets the JSON-serialized list of user claim types associated with this scope.
    /// </summary>
    public string UserClaimsJson { get; set; } = "[]";
}
