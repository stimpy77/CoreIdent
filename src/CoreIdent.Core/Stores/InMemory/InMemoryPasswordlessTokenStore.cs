using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Stores.InMemory;

public sealed class InMemoryPasswordlessTokenStore : IPasswordlessTokenStore
{
    private readonly ConcurrentDictionary<string, PasswordlessToken> _tokensByHash = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _attemptsByKey = new(StringComparer.OrdinalIgnoreCase);

    private readonly TimeProvider _timeProvider;
    private readonly IOptions<PasswordlessEmailOptions> _emailOptions;
    private readonly IOptions<PasswordlessSmsOptions> _smsOptions;

    public InMemoryPasswordlessTokenStore(
        TimeProvider? timeProvider,
        IOptions<PasswordlessEmailOptions> emailOptions,
        IOptions<PasswordlessSmsOptions> smsOptions)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _emailOptions = emailOptions;
        _smsOptions = smsOptions;
    }

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
            Email = recipient,
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

    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
    {
        return ValidateAndConsumeAsync(token, tokenType: null, recipient: null, ct);
    }

    public Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, string? tokenType, string? recipient, CancellationToken ct = default)
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

        var expectedType = NormalizeTokenType(tokenType);
        if (!string.IsNullOrWhiteSpace(expectedType) && !string.Equals(stored.TokenType, expectedType, StringComparison.Ordinal))
        {
            return Task.FromResult<PasswordlessToken?>(null);
        }

        if (!string.IsNullOrWhiteSpace(recipient) && !string.Equals(stored.Email, recipient.Trim(), StringComparison.OrdinalIgnoreCase))
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
