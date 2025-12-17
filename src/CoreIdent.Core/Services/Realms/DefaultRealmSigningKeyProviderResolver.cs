using CoreIdent.Core.Services;

namespace CoreIdent.Core.Services.Realms;

public sealed class DefaultRealmSigningKeyProviderResolver : IRealmSigningKeyProviderResolver
{
    private readonly ISigningKeyProvider _signingKeyProvider;

    public DefaultRealmSigningKeyProviderResolver(ISigningKeyProvider signingKeyProvider)
    {
        _signingKeyProvider = signingKeyProvider ?? throw new ArgumentNullException(nameof(signingKeyProvider));
    }

    public Task<ISigningKeyProvider> GetSigningKeyProviderAsync(string realmId, CancellationToken ct = default)
    {
        return Task.FromResult(_signingKeyProvider);
    }
}
