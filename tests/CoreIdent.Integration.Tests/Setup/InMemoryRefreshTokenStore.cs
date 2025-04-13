using CoreIdent.Core.Stores;
using CoreIdent.Core.Models;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace CoreIdent.Integration.Tests.Setup;

/// <summary>
/// Simple in-memory store for refresh tokens, suitable for testing purposes.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, CoreIdentRefreshToken> _tokens = new();

    public Task StoreRefreshTokenAsync(CoreIdentRefreshToken refreshToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        _tokens[refreshToken.Handle] = refreshToken;
        return Task.CompletedTask;
    }

    public Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshTokenHandle);
        _tokens.TryGetValue(refreshTokenHandle, out var token);
        return Task.FromResult(token);
    }

    public Task RemoveRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshTokenHandle);
        _tokens.TryRemove(refreshTokenHandle, out _);
        return Task.CompletedTask;
    }

    public Task UpdateRefreshTokenAsync(CoreIdentRefreshToken refreshToken, CancellationToken cancellationToken)
    {
        // For this simple store, update is the same as store
        return StoreRefreshTokenAsync(refreshToken, cancellationToken);
    }

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