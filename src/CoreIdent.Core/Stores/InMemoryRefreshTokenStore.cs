using CoreIdent.Core.Models;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System;
using System.Linq;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Simple default in-memory store for refresh tokens.
/// Suitable for basic scenarios or testing where persistence isn't required.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    // Use ConcurrentDictionary for basic thread safety
    private readonly ConcurrentDictionary<string, CoreIdentRefreshToken> _tokens = new();

    /// <inheritdoc />
    public Task StoreRefreshTokenAsync(CoreIdentRefreshToken refreshToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        _tokens[refreshToken.Handle] = refreshToken;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshTokenHandle);
        _tokens.TryGetValue(refreshTokenHandle, out var token);
        // Return a copy to prevent external modification of the stored object
        var tokenCopy = token == null ? null : new CoreIdentRefreshToken
        {
            Handle = token.Handle,
            ClientId = token.ClientId,
            SubjectId = token.SubjectId,
            CreationTime = token.CreationTime,
            ExpirationTime = token.ExpirationTime,
            ConsumedTime = token.ConsumedTime
        };
        return Task.FromResult(tokenCopy);
    }

    /// <inheritdoc />
    public Task RemoveRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshTokenHandle);
        _tokens.TryRemove(refreshTokenHandle, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateRefreshTokenAsync(CoreIdentRefreshToken refreshToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        if (!_tokens.ContainsKey(refreshToken.Handle))
        {
            // Or throw an exception, depending on desired behavior
            return Task.CompletedTask; 
        }
        _tokens[refreshToken.Handle] = refreshToken;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeRefreshTokensForUserAsync(string subjectId, string? clientId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);

        var keysToRemove = _tokens.Where(kvp =>
                kvp.Value.SubjectId == subjectId &&
                (clientId == null || kvp.Value.ClientId == clientId))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            _tokens.TryRemove(key, out _);
        }

        return Task.CompletedTask;
    }
} 