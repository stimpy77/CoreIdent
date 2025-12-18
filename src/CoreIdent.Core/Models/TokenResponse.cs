using System.Text.Json.Serialization;

namespace CoreIdent.Core.Models;

/// <summary>
/// OAuth 2.0 token response per RFC 6749.
/// </summary>
public record TokenResponse
{
    /// <summary>
    /// The access token issued by the authorization server.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>
    /// The type of the token issued (always "Bearer").
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// The lifetime in seconds of the access token.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; }

    /// <summary>
    /// The refresh token, which can be used to obtain new access tokens.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; init; }

    /// <summary>
    /// The scope of the access token (space-delimited).
    /// </summary>
    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; init; }

    /// <summary>
    /// ID token for OpenID Connect flows.
    /// </summary>
    [JsonPropertyName("id_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdToken { get; init; }
}

/// <summary>
/// OAuth 2.0 error response per RFC 6749.
/// </summary>
public record TokenErrorResponse
{
    /// <summary>
    /// Error code.
    /// </summary>
    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;

    /// <summary>
    /// Human-readable error description.
    /// </summary>
    [JsonPropertyName("error_description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// URI identifying a human-readable web page with error information.
    /// </summary>
    [JsonPropertyName("error_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorUri { get; init; }
}

/// <summary>
/// Standard OAuth 2.0 error codes per RFC 6749.
/// </summary>
public static class TokenErrors
{
    /// <summary>
    /// The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.
    /// </summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// Client authentication failed.
    /// </summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>
    /// The provided authorization grant or refresh token is invalid.
    /// </summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>
    /// The authenticated client is not authorized to use this authorization grant type.
    /// </summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>
    /// The authorization grant type is not supported by the authorization server.
    /// </summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>
    /// The requested scope is invalid.
    /// </summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>
    /// The authorization server encountered an unexpected condition.
    /// </summary>
    public const string ServerError = "server_error";
}
