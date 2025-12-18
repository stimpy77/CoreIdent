using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ITokenRevocationStore"/>.
/// </summary>
public sealed class InMemoryTokenRevocationStore : ITokenRevocationStore
{
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, RevokedTokenEntry> _revoked = new(StringComparer.Ordinal);
    private int _operationCount;

    /// <summary>
    /// Creates a new instance using <see cref="TimeProvider.System"/>.
    /// </summary>
    public InMemoryTokenRevocationStore()
        : this(timeProvider: null)
    {
    }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="timeProvider">Optional time provider; defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryTokenRevocationStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task RevokeTokenAsync(string jti, string tokenType, DateTime expiry, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new ArgumentException("JTI is required.", nameof(jti));
        }

        if (string.IsNullOrWhiteSpace(tokenType))
        {
            throw new ArgumentException("Token type is required.", nameof(tokenType));
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        if (expiry <= now)
        {
            return Task.CompletedTask;
        }

        _revoked[jti] = new RevokedTokenEntry(tokenType, expiry);

        MaybeCleanup(now);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            return Task.FromResult(false);
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        if (_revoked.TryGetValue(jti, out var entry))
        {
            if (entry.ExpiresAt <= now)
            {
                _revoked.TryRemove(jti, out _);
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc />
    public Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var (jti, entry) in _revoked)
        {
            if (entry.ExpiresAt <= now)
            {
                _revoked.TryRemove(jti, out _);
            }
        }

        return Task.CompletedTask;
    }

    private void MaybeCleanup(DateTime now)
    {
        if (Interlocked.Increment(ref _operationCount) % 100 != 0)
        {
            return;
        }

        foreach (var (jti, entry) in _revoked)
        {
            if (entry.ExpiresAt <= now)
            {
                _revoked.TryRemove(jti, out _);
            }
        }
    }

    private readonly record struct RevokedTokenEntry(string TokenType, DateTime ExpiresAt);
}
