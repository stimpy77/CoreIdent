using CoreIdent.Core.Services;

namespace CoreIdent.Core.Services.Realms;

public interface IRealmSigningKeyProviderResolver
{
    Task<ISigningKeyProvider> GetSigningKeyProviderAsync(string realmId, CancellationToken ct = default);
}
