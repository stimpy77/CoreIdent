using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware scope store for managing OAuth/OIDC scopes.
/// </summary>
public interface IRealmScopeStore
{
    /// <summary>
    /// Finds a scope by name within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="name">The scope name to find.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The scope if found, otherwise null.</returns>
    Task<CoreIdentScope?> FindByNameAsync(string realmId, string name, CancellationToken ct = default);
    
    /// <summary>
    /// Finds multiple scopes by their names within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="scopeNames">The scope names to find.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The found scopes.</returns>
    Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(string realmId, IEnumerable<string> scopeNames, CancellationToken ct = default);
    
    /// <summary>
    /// Gets all scopes within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>All scopes in the realm.</returns>
    Task<IEnumerable<CoreIdentScope>> GetAllAsync(string realmId, CancellationToken ct = default);
}
