using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Defines a realm-aware client store for managing OAuth clients.
/// </summary>
public interface IRealmClientStore
{
    /// <summary>
    /// Finds a client by client ID within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="clientId">The client ID to find.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>The client if found, otherwise null.</returns>
    Task<CoreIdentClient?> FindByClientIdAsync(string realmId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Validates a client secret within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="clientId">The client ID.</param>
    /// <param name="clientSecret">The client secret to validate.</param>
    /// <param name="ct">The cancellation token.</param>
    /// <returns>True if the client secret is valid, otherwise false.</returns>
    Task<bool> ValidateClientSecretAsync(string realmId, string clientId, string clientSecret, CancellationToken ct = default);

    /// <summary>
    /// Creates a new client within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="client">The client to create.</param>
    /// <param name="ct">The cancellation token.</param>
    Task CreateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default);

    /// <summary>
    /// Updates an existing client within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="client">The client to update.</param>
    /// <param name="ct">The cancellation token.</param>
    Task UpdateAsync(string realmId, CoreIdentClient client, CancellationToken ct = default);

    /// <summary>
    /// Deletes a client by client ID within the specified realm.
    /// </summary>
    /// <param name="realmId">The realm identifier.</param>
    /// <param name="clientId">The client ID to delete.</param>
    /// <param name="ct">The cancellation token.</param>
    Task DeleteAsync(string realmId, string clientId, CancellationToken ct = default);
}
