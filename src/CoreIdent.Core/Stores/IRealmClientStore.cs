using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmClientStore
{
    Task<CoreIdentClient?> FindByClientIdAsync(string realmId, string clientId, CancellationToken ct = default);

    Task<bool> ValidateClientSecretAsync(string realmId, string clientId, string clientSecret, CancellationToken ct = default);

    Task CreateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default);

    Task UpdateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default);

    Task DeleteAsync(string realmId, string clientId, CancellationToken ct = default);
}
