namespace CoreIdent.Client;

/// <summary>
/// Abstraction for storing OAuth/OIDC tokens.
/// </summary>
public interface ISecureTokenStorage
{
    /// <summary>
    /// Stores tokens.
    /// </summary>
    Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default);

    /// <summary>
    /// Gets stored tokens.
    /// </summary>
    Task<TokenSet?> GetTokensAsync(CancellationToken ct = default);

    /// <summary>
    /// Clears stored tokens.
    /// </summary>
    Task ClearTokensAsync(CancellationToken ct = default);
}
