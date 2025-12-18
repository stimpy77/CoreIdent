namespace CoreIdent.Core.Models;

/// <summary>
/// OAuth 2.0 token request per RFC 6749.
/// </summary>
public record TokenRequest
{
    /// <summary>
    /// The grant type being requested.
    /// </summary>
    public string GrantType { get; init; } = string.Empty;

    /// <summary>
    /// Client identifier (for client_credentials or when not using Basic auth).
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// Client secret (for confidential clients when not using Basic auth).
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// Requested scopes (space-delimited).
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Refresh token (for refresh_token grant).
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// Authorization code (for authorization_code grant).
    /// </summary>
    public string? Code { get; init; }

    /// <summary>
    /// Redirect URI (for authorization_code grant).
    /// </summary>
    public string? RedirectUri { get; init; }

    /// <summary>
    /// PKCE code verifier (for authorization_code grant with PKCE).
    /// </summary>
    public string? CodeVerifier { get; init; }

    /// <summary>
    /// Username (for password grant - deprecated but supported).
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// Password (for password grant - deprecated but supported).
    /// </summary>
    public string? Password { get; init; }
}

/// <summary>
/// Standard OAuth 2.0 grant types.
/// </summary>
public static class GrantTypes
{
    /// <summary>
    /// The <c>client_credentials</c> grant type.
    /// </summary>
    public const string ClientCredentials = "client_credentials";

    /// <summary>
    /// The <c>refresh_token</c> grant type.
    /// </summary>
    public const string RefreshToken = "refresh_token";

    /// <summary>
    /// The <c>authorization_code</c> grant type.
    /// </summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>
    /// The <c>password</c> grant type (deprecated).
    /// </summary>
    public const string Password = "password";

    /// <summary>
    /// The device authorization grant type.
    /// </summary>
    public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
}
