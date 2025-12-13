using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IScopeStore
{
    Task<CoreIdentScope?> FindByNameAsync(string name, CancellationToken ct = default);
    Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(IEnumerable<string> scopeNames, CancellationToken ct = default);
    Task<IEnumerable<CoreIdentScope>> GetAllAsync(CancellationToken ct = default);
}
