using System.Collections.Generic;

namespace CoreIdent.Core.Models;

/// <summary>
/// Models a scope, which represents a resource or identity information that a client can request access to.
/// </summary>
public class CoreIdentScope
{
    /// <summary>
    /// Scope name. This is the unique identifier for the scope.
    /// </summary>
    public string Name { get; set; } = default!;

    /// <summary>
    /// Display name. This value will be used e.g. on the consent screen.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Description. This value will be used e.g. on the consent screen.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Specifies whether the user can de-select the scope on the consent screen (if Required is false).
    /// Defaults to false.
    /// </summary>
    public bool Required { get; set; } = false;

    /// <summary>
    /// Specifies whether the consent screen will emphasize this scope (if Required is false).
    /// Use this setting for sensitive or important scopes. Defaults to false.
    /// </summary>
    public bool Emphasize { get; set; } = false;

    /// <summary>
    /// Specifies whether this scope is enabled (defaults to true).
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// List of user claim types that should be included in the identity token, access token, or userinfo endpoint response for this scope.
    /// </summary>
    public virtual ICollection<CoreIdentScopeClaim> UserClaims { get; set; } = new List<CoreIdentScopeClaim>();
}

/// <summary>
/// Represents a user claim associated with a scope.
/// </summary>
public class CoreIdentScopeClaim
{
    /// <summary>
    /// Primary key.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Foreign key to the Scope.
    /// </summary>
    public string ScopeName { get; set; } = default!;

    /// <summary>
    /// Scope this claim belongs to.
    /// </summary>
    public virtual CoreIdentScope Scope { get; set; } = default!;

    /// <summary>
    /// The type of the user claim.
    /// </summary>
    public string Type { get; set; } = default!;
} 