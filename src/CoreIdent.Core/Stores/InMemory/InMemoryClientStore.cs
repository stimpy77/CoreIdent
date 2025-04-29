using CoreIdent.Core.Models;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// Simple in-memory store for OAuth clients.
/// </summary>
public class InMemoryClientStore : IClientStore
{
    private readonly ConcurrentDictionary<string, CoreIdentClient> _clients = new(StringComparer.Ordinal);
    private readonly ILogger<InMemoryClientStore> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryClientStore"/> class.
    /// Optionally seeds initial clients.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="initialClients">Optional list of clients to seed.</param>
    public InMemoryClientStore(ILogger<InMemoryClientStore> logger, IEnumerable<CoreIdentClient>? initialClients = null)
    {
        _logger = logger;
        if (initialClients != null)
        {
            foreach (var client in initialClients)
            {
                if (!_clients.TryAdd(client.ClientId, client))
                {
                    _logger.LogWarning("Failed to add initial client with duplicate ClientId: {ClientId}", client.ClientId);
                }
                else
                {
                    _logger.LogDebug("Added initial client: {ClientId}", client.ClientId);
                }
            }
        }
    }

    /// <inheritdoc />
    public Task<CoreIdentClient?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        cancellationToken.ThrowIfCancellationRequested();

        _clients.TryGetValue(clientId, out var client);
        if (client != null)
        {
            _logger.LogDebug("Found client: {ClientId}", clientId);
            // Return a copy? For simplicity, returning direct reference.
            return Task.FromResult<CoreIdentClient?>(client);
        }
        else
        {
            _logger.LogDebug("Client not found: {ClientId}", clientId);
            return Task.FromResult<CoreIdentClient?>(null);
        }
    }

    // Optional: Add methods for managing clients if needed (e.g., AddClientAsync, UpdateClientAsync)
    public Task AddClientAsync(CoreIdentClient client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_clients.TryAdd(client.ClientId, client))
        {
            _logger.LogWarning("Client already exists: {ClientId}", client.ClientId);
            // Throw or return a specific result? Throwing for now.
            throw new InvalidOperationException($"Client with ID '{client.ClientId}' already exists.");
        }
        _logger.LogInformation("Added client: {ClientId}", client.ClientId);
        return Task.CompletedTask;
    }
}