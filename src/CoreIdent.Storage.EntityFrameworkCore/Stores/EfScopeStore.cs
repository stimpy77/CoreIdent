using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="IScopeStore"/>.
/// </summary>
public sealed class EfScopeStore : IScopeStore
{
    private readonly CoreIdentDbContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfScopeStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    public EfScopeStore(CoreIdentDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<CoreIdentScope?> FindByNameAsync(string name, CancellationToken ct = default)
    {
        var entity = await _context.Scopes
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Name == name, ct);

        return entity is null ? null : ToModel(entity);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<CoreIdentScope>> FindByScopesAsync(IEnumerable<string> scopeNames, CancellationToken ct = default)
    {
        var names = scopeNames.ToList();
        if (names.Count == 0)
        {
            return [];
        }

        var entities = await _context.Scopes
            .AsNoTracking()
            .Where(s => names.Contains(s.Name))
            .ToListAsync(ct);

        return entities.Select(ToModel);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<CoreIdentScope>> GetAllAsync(CancellationToken ct = default)
    {
        var entities = await _context.Scopes
            .AsNoTracking()
            .ToListAsync(ct);

        return entities.Select(ToModel);
    }

    private static CoreIdentScope ToModel(ScopeEntity entity) => new()
    {
        Name = entity.Name,
        DisplayName = entity.DisplayName,
        Description = entity.Description,
        Required = entity.Required,
        Emphasize = entity.Emphasize,
        ShowInDiscoveryDocument = entity.ShowInDiscoveryDocument,
        UserClaims = JsonSerializer.Deserialize<List<string>>(entity.UserClaimsJson) ?? []
    };
}
