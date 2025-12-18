namespace CoreIdent.Client;

/// <summary>
/// Represents a set of OAuth/OIDC tokens.
/// </summary>
public sealed record TokenSet
{
    /// <summary>
    /// Access token.
    /// </summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>
    /// Refresh token.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// ID token.
    /// </summary>
    public string? IdToken { get; init; }

    /// <summary>
    /// Space-delimited scopes that were granted.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Token type (typically "Bearer").
    /// </summary>
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// Access token expiration time (UTC).
    /// </summary>
    public DateTimeOffset ExpiresAtUtc { get; init; }
}
