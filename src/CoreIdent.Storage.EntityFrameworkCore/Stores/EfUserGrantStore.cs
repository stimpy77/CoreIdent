using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of <see cref="IUserGrantStore"/>.
/// </summary>
public sealed class EfUserGrantStore : IUserGrantStore
{
    private readonly CoreIdentDbContext _context;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfUserGrantStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    public EfUserGrantStore(CoreIdentDbContext context)
        : this(context, timeProvider: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EfUserGrantStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    /// <param name="timeProvider">An optional time provider.</param>
    public EfUserGrantStore(CoreIdentDbContext context, TimeProvider? timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<CoreIdentUserGrant?> FindAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId) || string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        var entity = await _context.UserGrants
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.SubjectId == subjectId && x.ClientId == clientId, ct);

        if (entity is null)
        {
            return null;
        }

        if (entity.ExpiresAt.HasValue && entity.ExpiresAt.Value <= _timeProvider.GetUtcNow().UtcDateTime)
        {
            return null;
        }

        return ToModel(entity);
    }

    /// <inheritdoc />
    public async Task SaveAsync(CoreIdentUserGrant grant, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentException.ThrowIfNullOrWhiteSpace(grant.SubjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(grant.ClientId);

        if (grant.CreatedAt == default)
        {
            grant.CreatedAt = _timeProvider.GetUtcNow().UtcDateTime;
        }

        var existing = await _context.UserGrants
            .FirstOrDefaultAsync(x => x.SubjectId == grant.SubjectId && x.ClientId == grant.ClientId, ct);

        if (existing is null)
        {
            _context.UserGrants.Add(ToEntity(grant));
        }
        else
        {
            existing.ScopesJson = JsonSerializer.Serialize(grant.Scopes);
            existing.CreatedAt = grant.CreatedAt;
            existing.ExpiresAt = grant.ExpiresAt;
        }

        await _context.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task RevokeAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId) || string.IsNullOrWhiteSpace(clientId))
        {
            return;
        }

        await _context.UserGrants
            .Where(x => x.SubjectId == subjectId && x.ClientId == clientId)
            .ExecuteDeleteAsync(ct);
    }

    /// <inheritdoc />
    public async Task<bool> HasUserGrantedConsentAsync(string subjectId, string clientId, IEnumerable<string> scopes, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var grant = await FindAsync(subjectId, clientId, ct);
        if (grant is null)
        {
            return false;
        }

        var granted = grant.Scopes.ToHashSet(StringComparer.Ordinal);
        return scopes.All(s => granted.Contains(s));
    }

    /// <inheritdoc />
    /// <remarks>
    /// This implementation uses a read-compute-write pattern. Under high concurrency for the same
    /// subject+client pair, a lost update is possible. For production systems with high consent
    /// concurrency, consider adding a rowversion/concurrency token to <c>UserGrantEntity</c>
    /// and handling <c>DbUpdateConcurrencyException</c> with a retry.
    /// </remarks>
    public async Task MergeScopesAsync(string subjectId, string clientId, IEnumerable<string> newScopes, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(newScopes);

        var existing = await _context.UserGrants
            .FirstOrDefaultAsync(x => x.SubjectId == subjectId && x.ClientId == clientId, ct);

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        if (existing is null)
        {
            _context.UserGrants.Add(new UserGrantEntity
            {
                SubjectId = subjectId,
                ClientId = clientId,
                ScopesJson = JsonSerializer.Serialize(newScopes.ToList()),
                CreatedAt = now
            });
        }
        else
        {
            var existingScopes = JsonSerializer.Deserialize<List<string>>(existing.ScopesJson) ?? [];
            var merged = existingScopes.Union(newScopes, StringComparer.Ordinal).ToList();
            existing.ScopesJson = JsonSerializer.Serialize(merged);
        }

        await _context.SaveChangesAsync(ct);
    }

    private static CoreIdentUserGrant ToModel(UserGrantEntity entity) => new()
    {
        SubjectId = entity.SubjectId,
        ClientId = entity.ClientId,
        Scopes = JsonSerializer.Deserialize<List<string>>(entity.ScopesJson) ?? [],
        CreatedAt = entity.CreatedAt,
        ExpiresAt = entity.ExpiresAt
    };

    private static UserGrantEntity ToEntity(CoreIdentUserGrant grant) => new()
    {
        SubjectId = grant.SubjectId,
        ClientId = grant.ClientId,
        ScopesJson = JsonSerializer.Serialize(grant.Scopes),
        CreatedAt = grant.CreatedAt,
        ExpiresAt = grant.ExpiresAt
    };
}
