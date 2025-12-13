using System.Collections.Concurrent;
using System.Security.Cryptography;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IRefreshTokenStore"/> for development and testing.
/// </summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, CoreIdentRefreshToken> _tokens = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private int _operationCount;

    public InMemoryRefreshTokenStore()
        : this(timeProvider: null)
    {
    }

    public InMemoryRefreshTokenStore(TimeProvider? timeProvider)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<string> StoreAsync(CoreIdentRefreshToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (string.IsNullOrWhiteSpace(token.Handle))
        {
            token.Handle = GenerateHandle();
        }

        _tokens[token.Handle] = token;

        MaybeCleanup();

        return Task.FromResult(token.Handle);
    }

    /// <inheritdoc />
    public Task<CoreIdentRefreshToken?> GetAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return Task.FromResult<CoreIdentRefreshToken?>(null);
        }

        _tokens.TryGetValue(handle, out var token);
        return Task.FromResult(token);
    }

    /// <inheritdoc />
    public Task<bool> RevokeAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return Task.FromResult(false);
        }

        if (_tokens.TryGetValue(handle, out var token))
        {
            token.IsRevoked = true;
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc />
    public Task RevokeFamilyAsync(string familyId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(familyId))
        {
            return Task.CompletedTask;
        }

        foreach (var token in _tokens.Values)
        {
            if (token.FamilyId == familyId)
            {
                token.IsRevoked = true;
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> ConsumeAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return Task.FromResult(false);
        }

        if (_tokens.TryGetValue(handle, out var token))
        {
            if (token.ConsumedAt.HasValue)
            {
                return Task.FromResult(false);
            }

            token.ConsumedAt = _timeProvider.GetUtcNow().UtcDateTime;
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc />
    public Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var (handle, token) in _tokens)
        {
            if (token.ExpiresAt <= now)
            {
                _tokens.TryRemove(handle, out _);
            }
        }

        return Task.CompletedTask;
    }

    private void MaybeCleanup()
    {
        if (Interlocked.Increment(ref _operationCount) % 100 != 0)
        {
            return;
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var (handle, token) in _tokens)
        {
            if (token.ExpiresAt <= now)
            {
                _tokens.TryRemove(handle, out _);
            }
        }
    }

    private static string GenerateHandle()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}
