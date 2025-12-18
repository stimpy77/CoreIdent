using System.Security.Cryptography;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of <see cref="IAuthorizationCodeStore"/>.
/// </summary>
public sealed class EfAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly CoreIdentDbContext _context;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfAuthorizationCodeStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    public EfAuthorizationCodeStore(CoreIdentDbContext context)
        : this(context, timeProvider: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EfAuthorizationCodeStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    /// <param name="timeProvider">An optional time provider.</param>
    public EfAuthorizationCodeStore(CoreIdentDbContext context, TimeProvider? timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task CreateAsync(CoreIdentAuthorizationCode code, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(code);

        if (string.IsNullOrWhiteSpace(code.Handle))
        {
            code.Handle = GenerateHandle();
        }

        if (code.CreatedAt == default)
        {
            code.CreatedAt = _timeProvider.GetUtcNow().UtcDateTime;
        }

        var entity = ToEntity(code);
        _context.AuthorizationCodes.Add(entity);
        await _context.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task<CoreIdentAuthorizationCode?> GetAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return null;
        }

        var entity = await _context.AuthorizationCodes
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Handle == handle, ct);

        return entity is null ? null : ToModel(entity);
    }

    /// <inheritdoc />
    public async Task<bool> ConsumeAsync(string handle, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        var affected = await _context.AuthorizationCodes
            .Where(x => x.Handle == handle && x.ConsumedAt == null && x.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), ct);

        return affected > 0;
    }

    /// <inheritdoc />
    public async Task CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        await _context.AuthorizationCodes
            .Where(x => x.ExpiresAt <= now)
            .ExecuteDeleteAsync(ct);
    }

    private static CoreIdentAuthorizationCode ToModel(AuthorizationCodeEntity entity) => new()
    {
        Handle = entity.Handle,
        ClientId = entity.ClientId,
        SubjectId = entity.SubjectId,
        RedirectUri = entity.RedirectUri,
        Scopes = JsonSerializer.Deserialize<List<string>>(entity.ScopesJson) ?? [],
        CreatedAt = entity.CreatedAt,
        ExpiresAt = entity.ExpiresAt,
        ConsumedAt = entity.ConsumedAt,
        Nonce = entity.Nonce,
        CodeChallenge = entity.CodeChallenge,
        CodeChallengeMethod = entity.CodeChallengeMethod
    };

    private static AuthorizationCodeEntity ToEntity(CoreIdentAuthorizationCode code) => new()
    {
        Handle = code.Handle,
        ClientId = code.ClientId,
        SubjectId = code.SubjectId,
        RedirectUri = code.RedirectUri,
        ScopesJson = JsonSerializer.Serialize(code.Scopes),
        CreatedAt = code.CreatedAt,
        ExpiresAt = code.ExpiresAt,
        ConsumedAt = code.ConsumedAt,
        Nonce = code.Nonce,
        CodeChallenge = code.CodeChallenge,
        CodeChallengeMethod = code.CodeChallengeMethod
    };

    private static string GenerateHandle()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }
}
