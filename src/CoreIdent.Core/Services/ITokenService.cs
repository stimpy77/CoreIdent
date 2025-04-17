using System.Threading.Tasks;
using CoreIdent.Core.Models; // Need CoreIdentUser
using System.Collections.Generic; // For IEnumerable

namespace CoreIdent.Core.Services;

/// <summary>
/// Provides an abstraction for generating security tokens.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Generates a JWT access token for the specified user, optionally including claims based on scopes.
    /// </summary>
    /// <param name="user">The user for whom to generate the token.</param>
    /// <param name="scopes">Optional. The scopes granted, used to determine claims in the token.</param>
    /// <returns>A task representing the asynchronous operation, containing the generated JWT access token.</returns>
    Task<string> GenerateAccessTokenAsync(CoreIdentUser user, IEnumerable<string>? scopes = null);

    /// <summary>
    /// Generates an OIDC ID token.
    /// </summary>
    /// <param name="user">The user (subject) of the token.</param>
    /// <param name="clientId">The client ID (audience) the token is intended for.</param>
    /// <param name="nonce">The nonce value from the authorization request (if any).</param>
    /// <param name="scopes">The scopes granted, used to determine claims in the token.</param>
    /// <returns>A task representing the asynchronous operation, containing the generated JWT ID token.</returns>
    Task<string> GenerateIdTokenAsync(CoreIdentUser user, string clientId, string? nonce, IEnumerable<string> scopes);

    /// <summary>
    /// Generates a secure refresh token handle and stores its details.
    /// This creates a new token family.
    /// </summary>
    /// <param name="user">The user for whom to generate the refresh token.</param>
    /// <param name="clientId">The client the refresh token is associated with.</param>
    /// <returns>A task representing the asynchronous operation, containing the generated refresh token handle (opaque string).</returns>
    Task<string> GenerateAndStoreRefreshTokenAsync(CoreIdentUser user, string clientId);

    /// <summary>
    /// Generates a secure refresh token handle as a descendant of a previous token and stores its details.
    /// Used during token rotation to maintain the token family lineage.
    /// </summary>
    /// <param name="user">The user for whom to generate the refresh token.</param>
    /// <param name="clientId">The client the refresh token is associated with.</param>
    /// <param name="previousToken">The previous token that is being rotated out.</param>
    /// <returns>A task representing the asynchronous operation, containing the generated refresh token handle (opaque string).</returns>
    Task<string> GenerateAndStoreRefreshTokenAsync(CoreIdentUser user, string clientId, CoreIdentRefreshToken previousToken);
}
