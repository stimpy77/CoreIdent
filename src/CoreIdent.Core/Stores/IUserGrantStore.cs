using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

public interface IUserGrantStore
{
    Task<CoreIdentUserGrant?> FindAsync(string subjectId, string clientId, CancellationToken ct = default);

    Task SaveAsync(CoreIdentUserGrant grant, CancellationToken ct = default);

    Task RevokeAsync(string subjectId, string clientId, CancellationToken ct = default);

    Task<bool> HasUserGrantedConsentAsync(string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default);
}
