using System.Collections.Concurrent;
using System.Security.Claims;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IUserStore"/>.
/// </summary>
public sealed class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, CoreIdentUser> _usersById = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _idByNormalizedUsername = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, List<Claim>> _claimsBySubjectId = new(StringComparer.Ordinal);

    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Creates a new instance using <see cref="TimeProvider.System"/>.
    /// </summary>
    public InMemoryUserStore()
        : this(timeProvider: null)
    {
    }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="timeProvider">Optional time provider; defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryUserStore(TimeProvider? timeProvider)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return Task.FromResult<CoreIdentUser?>(null);
        }

        _usersById.TryGetValue(id, out var user);
        return Task.FromResult(user);
    }

    /// <inheritdoc />
    public Task<CoreIdentUser?> FindByUsernameAsync(string username, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return Task.FromResult<CoreIdentUser?>(null);
        }

        var normalized = NormalizeUsername(username);
        if (!_idByNormalizedUsername.TryGetValue(normalized, out var id))
        {
            return Task.FromResult<CoreIdentUser?>(null);
        }

        return FindByIdAsync(id, ct);
    }

    /// <inheritdoc />
    public Task CreateAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrWhiteSpace(user.Id))
        {
            user.Id = Guid.NewGuid().ToString("N");
        }

        if (string.IsNullOrWhiteSpace(user.UserName))
        {
            throw new ArgumentException("UserName is required.", nameof(user));
        }

        var normalized = string.IsNullOrWhiteSpace(user.NormalizedUserName)
            ? NormalizeUsername(user.UserName)
            : user.NormalizedUserName;

        user.NormalizedUserName = normalized;

        if (!_idByNormalizedUsername.TryAdd(normalized, user.Id))
        {
            throw new InvalidOperationException($"User with username '{user.UserName}' already exists.");
        }

        if (!_usersById.TryAdd(user.Id, user))
        {
            _idByNormalizedUsername.TryRemove(normalized, out _);
            throw new InvalidOperationException($"User with id '{user.Id}' already exists.");
        }

        if (user.CreatedAt == default)
        {
            user.CreatedAt = _timeProvider.GetUtcNow().UtcDateTime;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Id);

        if (!_usersById.TryGetValue(user.Id, out _))
        {
            throw new InvalidOperationException($"User with id '{user.Id}' does not exist.");
        }

        if (string.IsNullOrWhiteSpace(user.UserName))
        {
            throw new ArgumentException("UserName is required.", nameof(user));
        }

        var normalized = string.IsNullOrWhiteSpace(user.NormalizedUserName)
            ? NormalizeUsername(user.UserName)
            : user.NormalizedUserName;

        user.NormalizedUserName = normalized;

        // The user instance in _usersById may be the same reference as the caller is mutating.
        // Determine the previous username mapping from the index itself.
        var previousNormalized = _idByNormalizedUsername
            .FirstOrDefault(kvp => string.Equals(kvp.Value, user.Id, StringComparison.Ordinal))
            .Key;

        if (!string.IsNullOrWhiteSpace(previousNormalized) &&
            !string.Equals(previousNormalized, normalized, StringComparison.Ordinal))
        {
            _idByNormalizedUsername.TryRemove(previousNormalized, out _);
        }

        _idByNormalizedUsername.AddOrUpdate(
            normalized,
            addValueFactory: _ => user.Id,
            updateValueFactory: (_, existingId) =>
            {
                if (!string.Equals(existingId, user.Id, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException($"User with username '{user.UserName}' already exists.");
                }

                return existingId;
            });

        _usersById[user.Id] = user;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeleteAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return Task.CompletedTask;
        }

        _usersById.TryRemove(id, out _);

        // Remove any username index entries pointing at this user id.
        foreach (var (normalizedUsername, existingId) in _idByNormalizedUsername)
        {
            if (string.Equals(existingId, id, StringComparison.Ordinal))
            {
                _idByNormalizedUsername.TryRemove(normalizedUsername, out _);
            }
        }

        _claimsBySubjectId.TryRemove(id, out _);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<Claim>> GetClaimsAsync(string subjectId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return Task.FromResult<IReadOnlyList<Claim>>([]);
        }

        if (_claimsBySubjectId.TryGetValue(subjectId, out var claims))
        {
            return Task.FromResult<IReadOnlyList<Claim>>(claims.ToList());
        }

        return Task.FromResult<IReadOnlyList<Claim>>([]);
    }

    /// <inheritdoc />
    public Task SetClaimsAsync(string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentNullException.ThrowIfNull(claims);

        _claimsBySubjectId[subjectId] = claims.ToList();
        return Task.CompletedTask;
    }

    private static string NormalizeUsername(string username) => username.Trim().ToUpperInvariant();
}
