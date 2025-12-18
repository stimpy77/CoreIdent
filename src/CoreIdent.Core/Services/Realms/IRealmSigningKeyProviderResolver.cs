using CoreIdent.Core.Services;

namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Resolves signing key providers for realm-aware token signing operations.
/// </summary>
public interface IRealmSigningKeyProviderResolver
{
    /// <summary>
    /// Gets the signing key provider for the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The signing key provider for the realm.</returns>
    Task<ISigningKeyProvider> GetSigningKeyProviderAsync(string realmId, CancellationToken ct = default);
}
