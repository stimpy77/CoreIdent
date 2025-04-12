using System.Threading.Tasks;
using CoreIdent.Core.Models; // Need CoreIdentUser

namespace CoreIdent.Core.Services;

/// <summary>
/// Provides an abstraction for generating security tokens.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Generates a JWT access token for the specified user.
    /// </summary>
    /// <param name="user">The user for whom to generate the token.</param>
    /// <returns>A task that represents the asynchronous operation, containing the generated JWT access token string.</returns>
    Task<string> GenerateAccessTokenAsync(CoreIdentUser user);

    /// <summary>
    /// Generates a refresh token (initially a simple secure random string).
    /// </summary>
    /// <param name="user">The user for whom to generate the refresh token.</param>
    /// <returns>A task that represents the asynchronous operation, containing the generated refresh token string.</returns>
    /// <remarks>The structure and handling of refresh tokens will become more complex in Phase 2.</remarks>
    Task<string> GenerateRefreshTokenAsync(CoreIdentUser user);
}
