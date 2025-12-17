namespace CoreIdent.Core.Services.Realms;

public interface IRealmIssuerAudienceProvider
{
    Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(string realmId, CancellationToken ct = default);
}
