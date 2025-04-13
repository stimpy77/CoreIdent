using CoreIdent.Core.Models;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides an abstraction for retrieving scope configuration.
/// </summary>
public interface IScopeStore
{
    /// <summary>
    /// Finds scopes by their names.
    /// </summary>
    /// <param name="scopeNames">The scope names to find.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing an enumeration of scopes found.</returns>
    Task<IEnumerable<CoreIdentScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken);

    /// <summary>
    /// Gets all defined scopes.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing an enumeration of all scopes.</returns>
    Task<IEnumerable<CoreIdentScope>> GetAllScopesAsync(CancellationToken cancellationToken);

    // Optional: Add methods for managing scopes (Create, Update, Delete) if needed.
} 