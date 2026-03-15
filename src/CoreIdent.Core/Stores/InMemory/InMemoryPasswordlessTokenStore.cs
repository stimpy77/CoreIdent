using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="IPasswordlessTokenStore"/>.
/// </summary>
public sealed class InMemoryPasswordlessTokenStore : IPasswordlessTokenStore
{
    private readonly ConcurrentDictionary<string, PasswordlessToken> _tokensByHash = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _attemptsByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _failedVerifyAttempts = new(StringComparer.OrdinalIgnoreCase);

    private readonly TimeProvider _timeProvider;
    private readonly IOptions<PasswordlessEmailOptions> _emailOptions;
    private readonly IOptions<PasswordlessSmsOptions> _smsOptions;

    /// <summary>
    /// Creates a new in-memory passwordless token store.
    /// </summary>
    /// <param name="timeProvider">Optional time provider; defaults to <see cref="TimeProvider.System"/>.</param>
    /// <param name="emailOptions">Email passwordless configuration.</param>
    /// <param name="smsOptions">SMS passwordless configuration.</param>
    public InMemoryPasswordlessTokenStore(
        TimeProvider? timeProvider,
        IOptions<PasswordlessEmailOptions> emailOptions,
        IOptions<PasswordlessSmsOptions> smsOptions)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _emailOptions = emailOptions;
        _smsOptions = smsOptions;
    }

    /// <inheritdoc />
    public Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        var tokenType = NormalizeTokenType(token.TokenType);

        var recipient = (token.Recipient ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(recipient))
        {
            throw new ArgumentException("Recipient is required.", nameof(token));
        }

        var now = _timeProvider.GetUtcNow();

        var (lifetime, maxAttemptsPerHour) = GetOptions(tokenType);
        EnforceRateLimit(BuildRateLimitKey(tokenType, recipient), now, maxAttemptsPerHour);

        var rawToken = tokenType == PasswordlessTokenTypes.SmsOtp
            ? GenerateOtp()
            : GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);

        var expiresAt = token.ExpiresAt == default
            ? now.Add(lifetime).UtcDateTime
            : token.ExpiresAt;

        var stored = new PasswordlessToken
        {
            Id = string.IsNullOrWhiteSpace(token.Id) ? Guid.NewGuid().ToString("N") : token.Id,
            Recipient = recipient,
            TokenType = tokenType,
            TokenHash = tokenHash,
            CreatedAt = token.CreatedAt == default ? now.UtcDateTime : token.CreatedAt,
            ExpiresAt = expiresAt,
            Consumed = false,
            UserId = token.UserId
        };

        _tokensByHash[tokenHash] = stored;

        return Task.FromResult(rawToken);
    }

    /// <inheritdoc />
    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
    {
        return ValidateAndConsumeAsync(token, tokenType: null, recipient: null, ct);
    }

    /// <inheritdoc />
    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, string? tokenType, string? recipient, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        var tokenHash = ComputeTokenHash(token);
        if (!_tokensByHash.TryGetValue(tokenHash, out var stored))
        {
            // Wrong token value — track failed attempt and burn if threshold exceeded
            RecordFailedVerifyAttempt(tokenType, recipient);
            return Task.FromResult<PasswordlessToken?>(null);
        }

        var expectedType = NormalizeTokenType(tokenType);
        if (!string.IsNullOrWhiteSpace(expectedType) && !string.Equals(stored.TokenType, expectedType, StringComparison.Ordinal))
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        if (!string.IsNullOrWhiteSpace(recipient) && !string.Equals(stored.Recipient, recipient.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        if (stored.ExpiresAt <= now)
        {
            _tokensByHash.TryRemove(tokenHash, out _);
            return Task.FromResult<PasswordlessToken?>(null);
        }

        lock (stored)
        {
            if (stored.Consumed)
            {
                return Task.FromResult<PasswordlessToken?>(null);
            }

            stored.Consumed = true;
        }

        // Successful validation — clear any failed attempt counter
        if (!string.IsNullOrWhiteSpace(tokenType) && !string.IsNullOrWhiteSpace(recipient))
        {
            _failedVerifyAttempts.TryRemove($"{tokenType}:{recipient.Trim()}", out _);
        }

        return Task.FromResult<PasswordlessToken?>(stored);
    }

    private void RecordFailedVerifyAttempt(string? tokenType, string? recipient)
    {
        if (string.IsNullOrWhiteSpace(tokenType) || string.IsNullOrWhiteSpace(recipient))
        {
            return;
        }

        var key = $"{tokenType}:{recipient.Trim()}";
        var maxAttempts = GetMaxVerifyAttempts(tokenType);

        var count = _failedVerifyAttempts.AddOrUpdate(key, 1, (_, prev) => prev + 1);
        if (count >= maxAttempts)
        {
            // Burn the real token: find by tokenType + recipient and mark consumed
            foreach (var kvp in _tokensByHash)
            {
                var t = kvp.Value;
                if (string.Equals(t.TokenType, tokenType, StringComparison.Ordinal)
                    && string.Equals(t.Recipient, recipient.Trim(), StringComparison.OrdinalIgnoreCase)
                    && !t.Consumed)
                {
                    lock (t)
                    {
                        t.Consumed = true;
                    }
                }
            }

            _failedVerifyAttempts.TryRemove(key, out _);
        }
    }

    private int GetMaxVerifyAttempts(string tokenType)
    {
        return string.Equals(tokenType, PasswordlessTokenTypes.SmsOtp, StringComparison.Ordinal)
            ? _smsOptions.Value.MaxVerifyAttempts
            : _emailOptions.Value.MaxVerifyAttempts;
    }

    /// <inheritdoc />
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

        var list = _attemptsByKey.GetOrAdd(email, _ => []);
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

    private static string NormalizeTokenType(string? tokenType)
    {
        if (string.IsNullOrWhiteSpace(tokenType))
        {
            return PasswordlessTokenTypes.EmailMagicLink;
        }

        return tokenType.Trim();
    }

    private (TimeSpan Lifetime, int MaxAttemptsPerHour) GetOptions(string tokenType)
    {
        if (string.Equals(tokenType, PasswordlessTokenTypes.SmsOtp, StringComparison.Ordinal))
        {
            var options = _smsOptions.Value;
            return (options.OtpLifetime, options.MaxAttemptsPerHour);
        }

        var email = _emailOptions.Value;
        return (email.TokenLifetime, email.MaxAttemptsPerHour);
    }

    private static string BuildRateLimitKey(string tokenType, string recipient)
    {
        return string.IsNullOrWhiteSpace(tokenType)
            ? recipient
            : $"{tokenType}:{recipient}";
    }

    private static string GenerateOtp()
    {
        var value = RandomNumberGenerator.GetInt32(0, 1_000_000);
        return value.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
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
