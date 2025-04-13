using CoreIdent.Core.Models;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides an abstraction for retrieving client configuration.
/// </summary>
public interface IClientStore
{
    /// <summary>
    /// Finds a client by its client ID.
    /// </summary>
    /// <param name="clientId">The client ID.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation, containing the client if found, otherwise null.</returns>
    Task<CoreIdentClient?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken);

    // Optional: Add methods for managing clients (Create, Update, Delete) if needed outside of direct DB manipulation.
} 