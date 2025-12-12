using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

public sealed class EfTokenRevocationStore : ITokenRevocationStore
{
    private readonly CoreIdentDbContext _db;
    private readonly TimeProvider _timeProvider;

    public EfTokenRevocationStore(CoreIdentDbContext db)
        : this(db, timeProvider: null)
    {
    }

    public EfTokenRevocationStore(CoreIdentDbContext db, TimeProvider? timeProvider)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task RevokeTokenAsync(string jti, string tokenType, DateTime expiry, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            throw new ArgumentException("JTI is required.", nameof(jti));
        }

        if (string.IsNullOrWhiteSpace(tokenType))
        {
            throw new ArgumentException("Token type is required.", nameof(tokenType));
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        if (expiry <= now)
        {
            return;
        }

        var existing = await _db.RevokedTokens.SingleOrDefaultAsync(x => x.Jti == jti, ct);

        if (existing is null)
        {
            _db.RevokedTokens.Add(new RevokedToken
            {
                Jti = jti,
                TokenType = tokenType,
                ExpiresAtUtc = expiry.ToUniversalTime(),
                RevokedAtUtc = now
            });
        }
        else
        {
            existing.TokenType = tokenType;
            existing.ExpiresAtUtc = expiry.ToUniversalTime();
            existing.RevokedAtUtc = now;
        }

        await _db.SaveChangesAsync(ct);
    }

    public async Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            return false;
        }

        var record = await _db.RevokedTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Jti == jti, ct);
        if (record is null)
        {
            return false;
        }

        if (record.ExpiresAtUtc <= _timeProvider.GetUtcNow().UtcDateTime)
        {
            return false;
        }

        return true;
    }

    public async Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        await _db.RevokedTokens
            .Where(x => x.ExpiresAtUtc <= now)
            .ExecuteDeleteAsync(ct);
    }
}
