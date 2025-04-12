using System;

namespace CoreIdent.Core.Models.Responses;

/// <summary>
/// DTO for responses containing access and refresh tokens.
/// </summary>
public record TokenResponse
{
    /// <summary>
    /// The JWT access token.
    /// </summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// The lifetime of the access token.
    /// </summary>
    public required TimeSpan AccessTokenLifetime { get; init; }

    /// <summary>
    /// The refresh token (handle).
    /// </summary>
    public required string RefreshToken { get; init; }

     /// <summary>
    /// The lifetime of the refresh token.
    /// </summary>
    public required TimeSpan RefreshTokenLifetime { get; init; }
}
