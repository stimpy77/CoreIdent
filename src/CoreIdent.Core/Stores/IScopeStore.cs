using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides access to configured OAuth/OIDC scopes.
/// </summary>
public interface IScopeStore
{
    /// <summary>
    /// Finds a scope by its name.
    /// </summary>
    /// <param name="name">The scope name.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The scope, or <see langword="null"/> if not found.</returns>
    Task<CoreIdentScope?> FindByNameAsync(string name, CancellationToken ct = default);

    /// <summary>
    /// Finds scopes by their names.
    /// </summary>
    /// <param name="scopeNames">The scope names.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The matching scopes.</returns>
    Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(IEnumerable<string> scopeNames, CancellationToken ct = default);

    /// <summary>
    /// Returns all configured scopes.
    /// </summary>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>All scopes.</returns>
    Task<IEnumerable<CoreIdentScope>> GetAllAsync(CancellationToken ct = default);
}
