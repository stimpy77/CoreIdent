namespace CoreIdent.Core.Services;

/// <summary>
/// Provides issuer and audience values for OAuth/OIDC tokens.
/// </summary>
public interface ICoreIdentIssuerAudienceProvider
{
    /// <summary>
    /// Gets the issuer and audience for token generation.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>A tuple containing the issuer and audience values.</returns>
    Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(CancellationToken ct = default);
}
