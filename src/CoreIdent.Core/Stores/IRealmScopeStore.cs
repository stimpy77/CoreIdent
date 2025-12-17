using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmScopeStore
{
    Task<CoreIdentScope?> FindByNameAsync(string realmId, string name, CancellationToken ct = default);
    Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(string realmId, IEnumerable<string> scopeNames, CancellationToken ct = default);
    Task<IEnumerable<CoreIdentScope>> GetAllAsync(string realmId, CancellationToken ct = default);
}
