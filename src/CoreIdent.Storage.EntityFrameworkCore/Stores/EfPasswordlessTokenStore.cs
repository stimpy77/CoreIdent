using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Configuration;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

public sealed class EfPasswordlessTokenStore : IPasswordlessTokenStore
{
    private readonly CoreIdentDbContext _context;
    private readonly TimeProvider _timeProvider;
    private readonly IOptions<PasswordlessEmailOptions> _emailOptions;

    public EfPasswordlessTokenStore(CoreIdentDbContext context, IOptions<PasswordlessEmailOptions> emailOptions)
        : this(context, emailOptions, timeProvider: null)
    {
    }

    public EfPasswordlessTokenStore(CoreIdentDbContext context, IOptions<PasswordlessEmailOptions> emailOptions, TimeProvider? timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _emailOptions = emailOptions ?? throw new ArgumentNullException(nameof(emailOptions));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<string> CreateTokenAsync(PasswordlessToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        var normalizedEmail = (token.Email ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalizedEmail))
        {
            throw new ArgumentException("Email is required.", nameof(token));
        }

        var options = _emailOptions.Value;
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        await EnforceRateLimitAsync(normalizedEmail, now, options.MaxAttemptsPerHour, ct);

        var rawToken = GenerateToken();
        var tokenHash = ComputeTokenHash(rawToken);

        var expiresAt = token.ExpiresAt == default
            ? _timeProvider.GetUtcNow().Add(options.TokenLifetime).UtcDateTime
            : token.ExpiresAt;

        var entity = new PasswordlessTokenEntity
        {
            Id = string.IsNullOrWhiteSpace(token.Id) ? Guid.NewGuid().ToString("N") : token.Id,
            Email = normalizedEmail,
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

    public async Task<PasswordlessToken?> ValidateAndConsumeAsync(string token, CancellationToken ct = default)
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
            TokenHash = entity.TokenHash,
            CreatedAt = entity.CreatedAt,
            ExpiresAt = entity.ExpiresAt,
            Consumed = true,
            UserId = entity.UserId
        };
    }

    public async Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        await _context.PasswordlessTokens
            .Where(t => t.ExpiresAt <= now)
            .ExecuteDeleteAsync(ct);
    }

    private async Task EnforceRateLimitAsync(string email, DateTime nowUtc, int maxAttemptsPerHour, CancellationToken ct)
    {
        if (maxAttemptsPerHour <= 0)
        {
            return;
        }

        var windowStart = nowUtc.AddHours(-1);

        var count = await _context.PasswordlessTokens
            .AsNoTracking()
            .Where(t => t.Email == email && t.CreatedAt >= windowStart)
            .CountAsync(ct);

        if (count >= maxAttemptsPerHour)
        {
            throw new PasswordlessRateLimitExceededException();
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
