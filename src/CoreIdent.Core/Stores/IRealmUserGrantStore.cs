using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IRealmUserGrantStore
{
    Task<CoreIdentUserGrant?> FindAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default);

    Task SaveAsync(string realmId, CoreIdentUserGrant grant, CancellationToken ct = default);

    Task RevokeAsync(string realmId, string subjectId, string clientId, CancellationToken ct = default);

    Task<bool> HasUserGrantedConsentAsync(string realmId, string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default);
}
