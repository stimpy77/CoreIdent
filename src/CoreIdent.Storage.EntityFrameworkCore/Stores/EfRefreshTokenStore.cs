using System.Security.Cryptography;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="IRefreshTokenStore"/>.
/// </summary>
public sealed class EfRefreshTokenStore : IRefreshTokenStore
{
    private readonly CoreIdentDbContext _context;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfRefreshTokenStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    public EfRefreshTokenStore(CoreIdentDbContext context)
        : this(context, timeProvider: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EfRefreshTokenStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    /// <param name="timeProvider">An optional time provider.</param>
    public EfRefreshTokenStore(CoreIdentDbContext context, TimeProvider? timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<string> StoreAsync(CoreIdentRefreshToken token, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (string.IsNullOrWhiteSpace(token.Handle))
        {
            token.Handle = GenerateHandle();
        }

        var entity = ToEntity(token);
        _context.RefreshTokens.Add(entity);
        await _context.SaveChangesAsync(ct);

        return token.Handle;
    }

    /// <inheritdoc />
    public async Task<CoreIdentRefreshToken?> GetAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return null;
        }

        var entity = await _context.RefreshTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Handle == handle, ct);

        return entity is null ? null : ToModel(entity);
    }

    /// <inheritdoc />
    public async Task<bool> RevokeAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return false;
        }

        var entity = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Handle == handle, ct);
        if (entity is null)
        {
            return false;
        }

        entity.IsRevoked = true;
        await _context.SaveChangesAsync(ct);
        return true;
    }

    /// <inheritdoc />
    public async Task RevokeFamilyAsync(string familyId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(familyId))
        {
            return;
        }

        await _context.RefreshTokens
            .Where(t => t.FamilyId == familyId)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsRevoked, true), ct);
    }

    /// <inheritdoc />
    public async Task<bool> ConsumeAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return false;
        }

        var entity = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Handle == handle, ct);
        if (entity is null || entity.ConsumedAt.HasValue)
        {
            return false;
        }

        entity.ConsumedAt = _timeProvider.GetUtcNow().UtcDateTime;
        await _context.SaveChangesAsync(ct);
        return true;
    }

    /// <inheritdoc />
    public async Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        await _context.RefreshTokens
            .Where(t => t.ExpiresAt <= now)
            .ExecuteDeleteAsync(ct);
    }

    private static CoreIdentRefreshToken ToModel(RefreshTokenEntity entity) => new()
    {
        Handle = entity.Handle,
        SubjectId = entity.SubjectId,
        ClientId = entity.ClientId,
        FamilyId = entity.FamilyId,
        Scopes = JsonSerializer.Deserialize<List<string>>(entity.ScopesJson) ?? [],
        CreatedAt = entity.CreatedAt,
        ExpiresAt = entity.ExpiresAt,
        ConsumedAt = entity.ConsumedAt,
        IsRevoked = entity.IsRevoked
    };

    private static RefreshTokenEntity ToEntity(CoreIdentRefreshToken token) => new()
    {
        Handle = token.Handle,
        SubjectId = token.SubjectId,
        ClientId = token.ClientId,
        FamilyId = token.FamilyId,
        ScopesJson = JsonSerializer.Serialize(token.Scopes),
        CreatedAt = token.CreatedAt,
        ExpiresAt = token.ExpiresAt,
        ConsumedAt = token.ConsumedAt,
        IsRevoked = token.IsRevoked
    };

    private static string GenerateHandle()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}
