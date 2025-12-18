namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Provides realm-specific issuer and audience values for OAuth/OIDC tokens.
/// </summary>
public interface IRealmIssuerAudienceProvider
{
    /// <summary>
    /// Gets the issuer and audience for the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A tuple containing the issuer and audience values.</returns>
    Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(string realmId, CancellationToken ct = default);
}
