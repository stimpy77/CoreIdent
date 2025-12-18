using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of <see cref="IPasswordlessTokenStore"/>.
/// </summary>
public sealed class EfPasswordlessTokenStore : IPasswordlessTokenStore
{
    private readonly CoreIdentDbContext _context;
    private readonly TimeProvider _timeProvider;
    private readonly IOptions<PasswordlessEmailOptions> _emailOptions;
    private readonly IOptions<PasswordlessSmsOptions> _smsOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfPasswordlessTokenStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    /// <param name="emailOptions">Passwordless email options.</param>
    /// <param name="smsOptions">Passwordless SMS options.</param>
    public EfPasswordlessTokenStore(
        CoreIdentDbContext context,
        IOptions<PasswordlessEmailOptions> emailOptions,
        IOptions<PasswordlessSmsOptions> smsOptions)
        : this(context, emailOptions, smsOptions, timeProvider: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EfPasswordlessTokenStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    /// <param name="emailOptions">Passwordless email options.</param>
    /// <param name="smsOptions">Passwordless SMS options.</param>
    /// <param name="timeProvider">An optional time provider.</param>
    public EfPasswordlessTokenStore(
        CoreIdentDbContext context,
        IOptions<PasswordlessEmailOptions> emailOptions,
        IOptions<PasswordlessSmsOptions> smsOptions,
        TimeProvider? timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _emailOptions = emailOptions ?? throw new ArgumentNullException(nameof(emailOptions));
        _smsOptions = smsOptions ?? throw new ArgumentNullException(nameof(smsOptions));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        var tokenType = NormalizeTokenType(token.TokenType);

        var recipient = (token.Recipient ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(recipient))
        {
            throw new ArgumentException("Recipient is required.", nameof(token));
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        var (lifetime, maxAttemptsPerHour) = GetOptions(tokenType);

        await EnforceRateLimitAsync(tokenType, recipient, now, maxAttemptsPerHour, ct);

        var rawToken = tokenType == PasswordlessTokenTypes.SmsOtp
            ? GenerateOtp()
            : GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);

        var expiresAt = token.ExpiresAt == default
            ? _timeProvider.GetUtcNow().Add(lifetime).UtcDateTime
            : token.ExpiresAt;

        var entity = new PasswordlessTokenEntity
        {
            Id = string.IsNullOrWhiteSpace(token.Id) ? Guid.NewGuid().ToString("N") : token.Id,
            Email = recipient,
            TokenType = tokenType,
            TokenHash = tokenHash,
            CreatedAt = token.CreatedAt == default ? now : token.CreatedAt,
            ExpiresAt = expiresAt,
            ConsumedAt = null,
            UserId = token.UserId
        };

        _context.PasswordlessTokens.Add(entity);
        await _context.SaveChangesAsync(ct);

        return rawToken;
    }

    /// <inheritdoc />
    public async Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
    {
        return await ValidateAndConsumeAsync(token, tokenType: null, recipient: null, ct);
    }

    /// <inheritdoc />
    public async Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, string? tokenType, string? recipient, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var tokenHash = ComputeTokenHash(token);
        var entity = await _context.PasswordlessTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);

        if (entity is null)
        {
            return null;
        }

        var expectedType = NormalizeTokenType(tokenType);
        if (!string.IsNullOrWhiteSpace(expectedType) && !string.Equals(entity.TokenType, expectedType, StringComparison.Ordinal))
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(recipient) && !string.Equals(entity.Email, recipient.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        if (entity.ExpiresAt <= now)
        {
            _context.PasswordlessTokens.Remove(entity);
            await _context.SaveChangesAsync(ct);
            return null;
        }

        if (entity.ConsumedAt.HasValue)
        {
            return null;
        }

        entity.ConsumedAt = now;
        await _context.SaveChangesAsync(ct);

        return new PasswordlessToken
        {
            Id = entity.Id,
            Email = entity.Email,
            TokenType = entity.TokenType,
            TokenHash = entity.TokenHash,
            CreatedAt = entity.CreatedAt,
            ExpiresAt = entity.ExpiresAt,
            Consumed = true,
            UserId = entity.UserId
        };
    }

    /// <inheritdoc />
    public async Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        await _context.PasswordlessTokens
            .Where(t => t.ExpiresAt <= now)
            .ExecuteDeleteAsync(ct);
    }

    private async Task EnforceRateLimitAsync(string tokenType, string recipient, DateTime nowUtc, int maxAttemptsPerHour, CancellationToken ct)
    {
        if (maxAttemptsPerHour <= 0)
        {
            return;
        }

        var windowStart = nowUtc.AddHours(-1);

        var count = await _context.PasswordlessTokens
            .AsNoTracking()
            .Where(t => t.TokenType == tokenType && t.Email == recipient && t.CreatedAt >= windowStart)
            .CountAsync(ct);

        if (count >= maxAttemptsPerHour)
        {
            throw new PasswordlessRateLimitExceededException();
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
