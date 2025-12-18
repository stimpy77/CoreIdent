namespace CoreIdent.Core.Models;

/// <summary>
/// Represents an OAuth/OIDC scope.
/// </summary>
public class CoreIdentScope
{
    /// <summary>
    /// The scope name.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Human-friendly display name.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Human-friendly description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Whether the scope is required.
    /// </summary>
    public bool Required { get; set; } = false;

    /// <summary>
    /// Whether to emphasize the scope when requesting consent.
    /// </summary>
    public bool Emphasize { get; set; } = false;

    /// <summary>
    /// Whether to include the scope in the discovery document.
    /// </summary>
    public bool ShowInDiscoveryDocument { get; set; } = true;

    /// <summary>
    /// Claims associated with the scope.
    /// </summary>
    public ICollection<string> UserClaims { get; set; } = [];
}
