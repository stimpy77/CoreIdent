using System.Collections.Concurrent;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IUserGrantStore"/>.
/// </summary>
public sealed class InMemoryUserGrantStore : IUserGrantStore
{
    private readonly ConcurrentDictionary<string, CoreIdentUserGrant> _grants = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="timeProvider">Optional time provider; defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryUserGrantStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<CoreIdentUserGrant?> FindAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId) || string.IsNullOrWhiteSpace(clientId))
        {
            return Task.FromResult<CoreIdentUserGrant?>(null);
        }

        _grants.TryGetValue(Key(subjectId, clientId), out var grant);

        if (grant is null)
        {
            return Task.FromResult<CoreIdentUserGrant?>(null);
        }

        if (grant.ExpiresAt.HasValue && grant.ExpiresAt.Value <= _timeProvider.GetUtcNow().UtcDateTime)
        {
            _grants.TryRemove(Key(subjectId, clientId), out _);
            return Task.FromResult<CoreIdentUserGrant?>(null);
        }

        return Task.FromResult<CoreIdentUserGrant?>(new CoreIdentUserGrant
        {
            SubjectId = grant.SubjectId,
            ClientId = grant.ClientId,
            Scopes = grant.Scopes.ToList(),
            CreatedAt = grant.CreatedAt,
            ExpiresAt = grant.ExpiresAt
        });
    }

    /// <inheritdoc />
    public Task SaveAsync(CoreIdentUserGrant grant, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentException.ThrowIfNullOrWhiteSpace(grant.SubjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(grant.ClientId);

        if (grant.CreatedAt == default)
        {
            grant.CreatedAt = _timeProvider.GetUtcNow().UtcDateTime;
        }

        _grants[Key(grant.SubjectId, grant.ClientId)] = new CoreIdentUserGrant
        {
            SubjectId = grant.SubjectId,
            ClientId = grant.ClientId,
            Scopes = grant.Scopes.ToList(),
            CreatedAt = grant.CreatedAt,
            ExpiresAt = grant.ExpiresAt
        };

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId) || string.IsNullOrWhiteSpace(clientId))
        {
            return Task.CompletedTask;
        }

        _grants.TryRemove(Key(subjectId, clientId), out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task<bool> HasUserGrantedConsentAsync(string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var grant = await FindAsync(subjectId, clientId, ct);
        if (grant is null)
        {
            return false;
        }

        var granted = grant.Scopes.ToHashSet(StringComparer.Ordinal);
        return scopes.All(s => granted.Contains(s));
    }

    private static string Key(string subjectId, string clientId) => $"{subjectId}::{clientId}";
}
