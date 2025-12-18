using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware passwordless token store for managing passwordless authentication tokens.
/// </summary>
public interface IRealmPasswordlessTokenStore
{
    /// <summary>
    /// Creates a passwordless token within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="token">The passwordless token to create.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The token handle.</returns>
    Task<string> CreateTokenAsync(string realmId, PasswordlessToken token, CancellationToken ct = default);

    /// <summary>
    /// Validates and consumes a passwordless token within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="token">The token to validate and consume.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The passwordless token if valid, otherwise null.</returns>
    Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, CancellationToken ct = default);

    /// <summary>
    /// Validates and consumes a passwordless token with additional parameters within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="token">The token to validate and consume.</param>
    /// <param name="tokenType">The optional token type to validate.</param>
    /// <param name="recipient">The optional recipient to validate.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The passwordless token if valid, otherwise null.</returns>
    Task<PasswordlessToken?> ValidateAndConsumeAsync(string realmId, string token, string? tokenType, string? recipient, CancellationToken ct = default);

    /// <summary>
    /// Cleans up expired passwordless tokens within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(string realmId, CancellationToken ct = default);
}
