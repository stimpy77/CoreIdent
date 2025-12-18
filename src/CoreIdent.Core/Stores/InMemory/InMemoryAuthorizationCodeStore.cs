using System.Collections.Concurrent;
using System.Security.Cryptography;
using CoreIdent.Core.Models;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IAuthorizationCodeStore"/>.
/// </summary>
public sealed class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, CoreIdentAuthorizationCode> _codes = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="timeProvider">Optional time provider; defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryAuthorizationCodeStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task CreateAsync(CoreIdentAuthorizationCode code, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(code);

        if (string.IsNullOrWhiteSpace(code.Handle))
        {
            code.Handle = GenerateHandle();
        }

        if (code.CreatedAt == default)
        {
            code.CreatedAt = _timeProvider.GetUtcNow().UtcDateTime;
        }

        if (!_codes.TryAdd(code.Handle, code))
        {
            throw new InvalidOperationException($"Authorization code with handle '{code.Handle}' already exists.");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<CoreIdentAuthorizationCode?> GetAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return Task.FromResult<CoreIdentAuthorizationCode?>(null);
        }

        _codes.TryGetValue(handle, out var code);
        return Task.FromResult(code);
    }

    /// <inheritdoc />
    public Task<bool> ConsumeAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return Task.FromResult(false);
        }

        if (!_codes.TryGetValue(handle, out var code))
        {
            return Task.FromResult(false);
        }

        if (code.ConsumedAt.HasValue)
        {
            return Task.FromResult(false);
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        if (code.ExpiresAt <= now)
        {
            return Task.FromResult(false);
        }

        code.ConsumedAt = now;
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var (handle, code) in _codes)
        {
            if (code.ExpiresAt <= now)
            {
                _codes.TryRemove(handle, out _);
            }
        }

        return Task.CompletedTask;
    }

    private static string GenerateHandle()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}
