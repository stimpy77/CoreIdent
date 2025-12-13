using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Store for managing OAuth 2.0 / OIDC client applications.
/// </summary>
public interface IClientStore
{
    /// <summary>
    /// Finds a client by its client ID.
    /// </summary>
    Task<CoreIdentClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default);

    /// <summary>
    /// Validates a client's secret.
    /// </summary>
    /// <returns>True if the secret is valid, false otherwise.</returns>
    Task<bool> ValidateClientSecretAsync(string clientId, string clientSecret, CancellationToken ct = default);

    /// <summary>
    /// Creates a new client.
    /// </summary>
    Task CreateAsync(CoreIdentClient client, CancellationToken ct = default);

    /// <summary>
    /// Updates an existing client.
    /// </summary>
    Task UpdateAsync(CoreIdentClient client, CancellationToken ct = default);

    /// <summary>
    /// Deletes a client by its client ID.
    /// </summary>
    Task DeleteAsync(string clientId, CancellationToken ct = default);
}
