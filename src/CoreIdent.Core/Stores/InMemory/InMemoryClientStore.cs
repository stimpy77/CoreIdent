using System.Collections.Concurrent;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IClientStore"/> for development and testing.
/// </summary>
public sealed class InMemoryClientStore : IClientStore
{
    private readonly ConcurrentDictionary<string, CoreIdentClient> _clients = new(StringComparer.Ordinal);
    private readonly IClientSecretHasher _secretHasher;

    public InMemoryClientStore(IClientSecretHasher secretHasher)
    {
        _secretHasher = secretHasher ?? throw new ArgumentNullException(nameof(secretHasher));
    }

    /// <summary>
    /// Seeds the store with initial clients. Useful for testing and development.
    /// </summary>
    public void SeedClients(IEnumerable<CoreIdentClient> clients)
    {
        foreach (var client in clients)
        {
            _clients.TryAdd(client.ClientId, client);
        }
    }

    /// <summary>
    /// Seeds a client with a plaintext secret (will be hashed).
    /// </summary>
    public void SeedClientWithSecret(CoreIdentClient client, string plaintextSecret)
    {
        client.ClientSecretHash = _secretHasher.HashSecret(plaintextSecret);
        _clients.TryAdd(client.ClientId, client);
    }

    /// <inheritdoc />
    public Task<CoreIdentClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }

    /// <inheritdoc />
    public Task<bool> ValidateClientSecretAsync(string clientId, string clientSecret, CancellationToken ct = default)
    {
        if (!_clients.TryGetValue(clientId, out var client))
        {
            return Task.FromResult(false);
        }

        if (client.ClientType == ClientType.Public)
        {
            // Public clients don't have secrets
            return Task.FromResult(true);
        }

        if (string.IsNullOrWhiteSpace(client.ClientSecretHash))
        {
            return Task.FromResult(false);
        }

        var isValid = _secretHasher.VerifySecret(clientSecret, client.ClientSecretHash);
        return Task.FromResult(isValid);
    }

    /// <inheritdoc />
    public Task CreateAsync(CoreIdentClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(client.ClientId);

        if (!_clients.TryAdd(client.ClientId, client))
        {
            throw new InvalidOperationException($"Client with ID '{client.ClientId}' already exists.");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateAsync(CoreIdentClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(client.ClientId);

        if (!_clients.ContainsKey(client.ClientId))
        {
            throw new InvalidOperationException($"Client with ID '{client.ClientId}' does not exist.");
        }

        _clients[client.ClientId] = client;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeleteAsync(string clientId, CancellationToken ct = default)
    {
        _clients.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}
