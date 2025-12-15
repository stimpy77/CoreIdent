using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Stores.InMemory;

public sealed class InMemoryPasswordlessTokenStore : IPasswordlessTokenStore
{
    private readonly ConcurrentDictionary<string, PasswordlessToken> _tokensByHash = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _attemptsByEmail = new(StringComparer.OrdinalIgnoreCase);

    private readonly TimeProvider _timeProvider;
    private readonly IOptions<PasswordlessEmailOptions> _emailOptions;

    public InMemoryPasswordlessTokenStore(TimeProvider? timeProvider, IOptions<PasswordlessEmailOptions> emailOptions)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _emailOptions = emailOptions;
    }

    public Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        var normalizedEmail = (token.Email ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalizedEmail))
        {
            throw new ArgumentException("Email is required.", nameof(token));
        }

        var options = _emailOptions.Value;
        var now = _timeProvider.GetUtcNow();

        EnforceRateLimit(normalizedEmail, now, options.MaxAttemptsPerHour);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);

        var expiresAt = token.ExpiresAt == default
            ? now.Add(options.TokenLifetime).UtcDateTime
            : token.ExpiresAt;

        var stored = new PasswordlessToken
        {
            Id = string.IsNullOrWhiteSpace(token.Id) ? Guid.NewGuid().ToString("N") : token.Id,
            Email = normalizedEmail,
            TokenHash = tokenHash,
            CreatedAt = token.CreatedAt == default ? now.UtcDateTime : token.CreatedAt,
            ExpiresAt = expiresAt,
            Consumed = false,
            UserId = token.UserId
        };

        _tokensByHash[tokenHash] = stored;

        return Task.FromResult(rawToken);
    }

    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        var tokenHash = ComputeTokenHash(token);
        if (!_tokensByHash.TryGetValue(tokenHash, out var stored))
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        if (stored.ExpiresAt <= now)
        {
            _tokensByHash.TryRemove(tokenHash, out _);
            return Task.FromResult<PasswordlessToken?>(null);
        }

        if (stored.Consumed)
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        stored.Consumed = true;
        return Task.FromResult<PasswordlessToken?>(stored);
    }

    public Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var kvp in _tokensByHash)
        {
            if (kvp.Value.ExpiresAt <= now)
            {
                _tokensByHash.TryRemove(kvp.Key, out _);
            }
        }

        return Task.CompletedTask;
    }

    private void EnforceRateLimit(string email, DateTimeOffset now, int maxAttemptsPerHour)
    {
        if (maxAttemptsPerHour <= 0)
        {
            return;
        }

        var list = _attemptsByEmail.GetOrAdd(email, _ => []);
        lock (list)
        {
            var windowStart = now.AddHours(-1);
            list.RemoveAll(x => x < windowStart);

            if (list.Count >= maxAttemptsPerHour)
            {
                throw new CoreIdent.Core.Stores.PasswordlessRateLimitExceededException();
            }

            list.Add(now);
        }
    }

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string ComputeTokenHash(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
