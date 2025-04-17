using System;
using System.Text.Json.Serialization; // For JsonPropertyName

namespace CoreIdent.Core.Models.Responses;

/// <summary>
/// DTO representing the standard OAuth 2.0 / OIDC token response.
/// See: https://tools.ietf.org/html/rfc6749#section-5.1
/// </summary>
public record TokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    // Standard token type, almost always "Bearer"
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    // Lifetime in seconds
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    // Optional: Only included if requested and allowed
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    // Optional: Included for OIDC flows
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }

    // Optional: Included if different from initially requested scopes
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    // Non-standard properties removed:
    // public required TimeSpan AccessTokenLifetime { get; init; }
    // public required TimeSpan RefreshTokenLifetime { get; init; }
}
