using CoreIdent.Core.Services.Realms;

namespace CoreIdent.Core.Services;

/// <summary>
/// Default implementation that provides issuer and audience values using realm context.
/// </summary>
public sealed class DefaultCoreIdentIssuerAudienceProvider : ICoreIdentIssuerAudienceProvider
{
    private readonly ICoreIdentRealmContext _realmContext;
    private readonly IRealmIssuerAudienceProvider _realmIssuerAudienceProvider;

    /// <summary>
    /// Initializes a new instance of <see cref="DefaultCoreIdentIssuerAudienceProvider"/> class.
    /// </summary>
    /// <param name="realmContext">The realm context.</param>
    /// <param name="realmIssuerAudienceProvider">The realm-specific issuer audience provider.</param>
    public DefaultCoreIdentIssuerAudienceProvider(
        ICoreIdentRealmContext realmContext,
        IRealmIssuerAudienceProvider realmIssuerAudienceProvider)
    {
        _realmContext = realmContext ?? throw new ArgumentNullException(nameof(realmContext));
        _realmIssuerAudienceProvider = realmIssuerAudienceProvider ?? throw new ArgumentNullException(nameof(realmIssuerAudienceProvider));
    }

    /// <inheritdoc />
    public Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(CancellationToken ct = default)
    {
        return _realmIssuerAudienceProvider.GetIssuerAndAudienceAsync(_realmContext.RealmId, ct);
    }
}
