using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Persists and validates passwordless authentication tokens.
/// </summary>
public interface IPasswordlessTokenStore
{
    /// <summary>
    /// Creates and stores a passwordless token and returns the token string to deliver to the recipient.
    /// </summary>
    /// <param name="token">The token metadata to store.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The token string that can be presented for validation.</returns>
    Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default);

    /// <summary>
    /// Validates a token and marks it as consumed if valid.
    /// </summary>
    /// <param name="token">The token string.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The consumed token details, or <see langword="null"/> if invalid/expired/already consumed.</returns>
    Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default);

    /// <summary>
    /// Validates a token with optional context (type/recipient) and marks it as consumed if valid.
    /// </summary>
    /// <param name="token">The token string.</param>
    /// <param name="tokenType">Optional token type discriminator.</param>
    /// <param name="recipient">Optional recipient discriminator.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The consumed token details, or <see langword="null"/> if invalid/expired/already consumed.</returns>
    Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, string? tokenType, string? recipient, CancellationToken ct = default);

    /// <summary>
    /// Removes expired passwordless tokens.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    Task CleanupExpiredAsync(CancellationToken ct = default);
}
