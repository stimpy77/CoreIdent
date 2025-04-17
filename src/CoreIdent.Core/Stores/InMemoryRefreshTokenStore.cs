using CoreIdent.Core.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Simple in-memory store for refresh tokens.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    // Key: Refresh Token Hashed Handle
    private readonly ConcurrentDictionary<string, CoreIdentRefreshToken> _tokens = new();
    private readonly ILogger<InMemoryRefreshTokenStore> _logger;

    public InMemoryRefreshTokenStore(ILogger<InMemoryRefreshTokenStore> logger)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StoreRefreshTokenAsync(CoreIdentRefreshToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        cancellationToken.ThrowIfCancellationRequested();

        // Use the Handle property as the key, which is now expected to contain the hashed value
        string tokenKey = token.Handle;
        
        // Optional: If HashedHandle is set, use that instead (for future compatibility)
        if (!string.IsNullOrEmpty(token.HashedHandle))
        {
            tokenKey = token.HashedHandle;
        }

        _tokens[tokenKey] = token;
        _logger.LogDebug("Stored refresh token with hashed handle: {HashedHandle}, Expires: {Expiry}", 
            tokenKey.Substring(0, Math.Min(6, tokenKey.Length)), token.ExpirationTime);

        // Simple cleanup for expired tokens (run occasionally or on access)
        // A more robust system would use a background task or timed service.
        CleanUpExpiredTokens();

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<CoreIdentRefreshToken?> GetRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        cancellationToken.ThrowIfCancellationRequested();

        // tokenHandle parameter now contains the hashed value from TokenHasher (caller's responsibility)
        if (_tokens.TryGetValue(tokenHandle, out var token))
        {
            if (token.ExpirationTime < DateTime.UtcNow)
            {
                _logger.LogDebug("Attempted to retrieve expired refresh token. Hashed handle: {HashedHandle}", 
                    tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
                _tokens.TryRemove(tokenHandle, out _); // Remove if expired
                return Task.FromResult<CoreIdentRefreshToken?>(null);
            }
            
            // Check if consumed (this might be handled by RemoveRefreshTokenAsync primarily)
            if (token.ConsumedTime.HasValue)
            {
                _logger.LogWarning("Attempted to retrieve already consumed refresh token. Hashed handle: {HashedHandle}", 
                    tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
                // Depending on policy, might return null or keep it for analysis.
                // Returning null is safer for preventing reuse.
                return Task.FromResult<CoreIdentRefreshToken?>(null);
            }

            _logger.LogDebug("Retrieved refresh token. Hashed handle: {HashedHandle}", 
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
            return Task.FromResult<CoreIdentRefreshToken?>(token);
        }

        _logger.LogDebug("Refresh token not found. Hashed handle: {HashedHandle}", 
            tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        return Task.FromResult<CoreIdentRefreshToken?>(null);
    }

    /// <inheritdoc />
    public Task RemoveRefreshTokenAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        cancellationToken.ThrowIfCancellationRequested();

        // tokenHandle parameter now contains the hashed value from TokenHasher (caller's responsibility)
        if (_tokens.TryGetValue(tokenHandle, out var token))
        {
            // Mark as consumed instead of removing for audit trail and token theft detection
            token.ConsumedTime = DateTime.UtcNow;
            _tokens[tokenHandle] = token; // Update with consumed state
            _logger.LogDebug("Marked refresh token as consumed. Hashed handle: {HashedHandle}", 
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        else
        {
            _logger.LogDebug("Attempted to remove non-existent refresh token. Hashed handle: {HashedHandle}", 
                tokenHandle.Substring(0, Math.Min(6, tokenHandle.Length)));
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateRefreshTokenAsync(CoreIdentRefreshToken refreshToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        
        string tokenKey = refreshToken.Handle;
        // If HashedHandle is set, prefer it
        if (!string.IsNullOrEmpty(refreshToken.HashedHandle))
        {
            tokenKey = refreshToken.HashedHandle;
        }
        
        if (!_tokens.ContainsKey(tokenKey))
        {
            // Or throw an exception, depending on desired behavior
            return Task.CompletedTask; 
        }
        
        _tokens[tokenKey] = refreshToken;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeRefreshTokensForUserAsync(string subjectId, string? clientId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);

        var keysToUpdate = _tokens.Where(kvp =>
                kvp.Value.SubjectId == subjectId &&
                (clientId == null || kvp.Value.ClientId == clientId) &&
                !kvp.Value.ConsumedTime.HasValue)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToUpdate)
        {
            if (_tokens.TryGetValue(key, out var token))
            {
                token.ConsumedTime = DateTime.UtcNow;
                _tokens[key] = token;
            }
        }

        _logger.LogInformation("Revoked {Count} refresh tokens for user {SubjectId}", keysToUpdate.Count, subjectId);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeTokenFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        var keysToUpdate = _tokens.Where(kvp => 
                kvp.Value.FamilyId == familyId && 
                !kvp.Value.ConsumedTime.HasValue)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToUpdate)
        {
            if (_tokens.TryGetValue(key, out var token))
            {
                token.ConsumedTime = DateTime.UtcNow;
                _tokens[key] = token;
            }
        }

        _logger.LogWarning("Revoked {Count} refresh tokens from family {FamilyId} due to potential token theft", keysToUpdate.Count, familyId);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IEnumerable<CoreIdentRefreshToken>> FindTokensBySubjectIdAsync(string subjectId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        cancellationToken.ThrowIfCancellationRequested();

        var tokens = _tokens.Values
            .Where(t => t.SubjectId == subjectId)
            .ToList();

        return Task.FromResult<IEnumerable<CoreIdentRefreshToken>>(tokens);
    }

    private void CleanUpExpiredTokens()
    {
        // Basic cleanup - not highly efficient for large collections.
        // Only remove tokens that are both expired and consumed (for audit trail)
        var expiredKeys = _tokens.Where(pair => 
                pair.Value.ExpirationTime < DateTime.UtcNow && 
                pair.Value.ConsumedTime.HasValue && 
                pair.Value.ConsumedTime.Value.AddDays(7) < DateTime.UtcNow) // Keep consumed tokens for 7 days
            .Select(pair => pair.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            if (_tokens.TryRemove(key, out _))
            {
                _logger.LogDebug("Cleaned up expired and consumed refresh token. Hashed handle: {HashedHandle}", 
                    key.Substring(0, Math.Min(6, key.Length)));
            }
        }
    }
} 