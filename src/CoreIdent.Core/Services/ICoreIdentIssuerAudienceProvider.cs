namespace CoreIdent.Core.Services;

public interface ICoreIdentIssuerAudienceProvider
{
    Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(CancellationToken ct = default);
}
