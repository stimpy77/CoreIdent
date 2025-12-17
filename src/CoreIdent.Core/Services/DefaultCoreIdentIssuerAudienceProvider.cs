using CoreIdent.Core.Services.Realms;

namespace CoreIdent.Core.Services;

public sealed class DefaultCoreIdentIssuerAudienceProvider : ICoreIdentIssuerAudienceProvider
{
    private readonly ICoreIdentRealmContext _realmContext;
    private readonly IRealmIssuerAudienceProvider _realmIssuerAudienceProvider;

    public DefaultCoreIdentIssuerAudienceProvider(
        ICoreIdentRealmContext realmContext,
        IRealmIssuerAudienceProvider realmIssuerAudienceProvider)
    {
        _realmContext = realmContext ?? throw new ArgumentNullException(nameof(realmContext));
        _realmIssuerAudienceProvider = realmIssuerAudienceProvider ?? throw new ArgumentNullException(nameof(realmIssuerAudienceProvider));
    }

    public Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(CancellationToken ct = default)
    {
        return _realmIssuerAudienceProvider.GetIssuerAndAudienceAsync(_realmContext.RealmId, ct);
    }
}
