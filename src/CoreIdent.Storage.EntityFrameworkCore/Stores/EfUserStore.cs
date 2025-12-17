using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

public sealed class EfUserStore : IUserStore
{
    private readonly CoreIdentDbContext _context;

    private readonly TimeProvider _timeProvider;

    public EfUserStore(CoreIdentDbContext context, TimeProvider timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<CoreIdentUser?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        var entity = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == id, ct);

        return entity is null ? null : ToModel(entity);
    }

    public async Task<CoreIdentUser?> FindByUsernameAsync(string username, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        var normalized = NormalizeUsername(username);
        var entity = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.NormalizedUserName == normalized, ct);

        return entity is null ? null : ToModel(entity);
    }

    public async Task CreateAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrWhiteSpace(user.Id))
        {
            user.Id = Guid.NewGuid().ToString("N");
        }

        if (string.IsNullOrWhiteSpace(user.UserName))
        {
            throw new ArgumentException("UserName is required.", nameof(user));
        }

        user.NormalizedUserName = NormalizeUsername(user.UserName);

        if (user.CreatedAt == default)
        {
            user.CreatedAt = _timeProvider.GetUtcNow().UtcDateTime;
        }

        var entity = ToEntity(user);
        _context.Users.Add(entity);
        await _context.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(CoreIdentUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(user.Id);

        var entity = await _context.Users.FirstOrDefaultAsync(u => u.Id == user.Id, ct)
            ?? throw new InvalidOperationException($"User with id '{user.Id}' does not exist.");

        if (string.IsNullOrWhiteSpace(user.UserName))
        {
            throw new ArgumentException("UserName is required.", nameof(user));
        }

        user.NormalizedUserName = NormalizeUsername(user.UserName);

        UpdateEntity(entity, user);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return;
        }

        var entity = await _context.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (entity is not null)
        {
            _context.Users.Remove(entity);
            await _context.SaveChangesAsync(ct);
        }
    }

    public async Task<IReadOnlyList<Claim>> GetClaimsAsync(string subjectId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            return [];
        }

        var entity = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == subjectId, ct);

        if (entity is null)
        {
            return [];
        }

        var dtos = JsonSerializer.Deserialize<List<ClaimDto>>(entity.ClaimsJson) ?? [];
        return dtos.Select(c => new Claim(c.Type, c.Value)).ToList();
    }

    public async Task SetClaimsAsync(string subjectId, IEnumerable<Claim> claims, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentNullException.ThrowIfNull(claims);

        var entity = await _context.Users.FirstOrDefaultAsync(u => u.Id == subjectId, ct)
            ?? throw new InvalidOperationException($"User with id '{subjectId}' does not exist.");

        var dtos = claims.Select(c => new ClaimDto(c.Type, c.Value)).ToList();
        entity.ClaimsJson = JsonSerializer.Serialize(dtos);
        await _context.SaveChangesAsync(ct);
    }

    private static CoreIdentUser ToModel(UserEntity entity) => new()
    {
        Id = entity.Id,
        UserName = entity.UserName,
        NormalizedUserName = entity.NormalizedUserName,
        PasswordHash = entity.PasswordHash,
        CreatedAt = entity.CreatedAt,
        UpdatedAt = entity.UpdatedAt
    };

    private static UserEntity ToEntity(CoreIdentUser user) => new()
    {
        Id = user.Id,
        UserName = user.UserName,
        NormalizedUserName = user.NormalizedUserName,
        PasswordHash = user.PasswordHash,
        CreatedAt = user.CreatedAt,
        UpdatedAt = user.UpdatedAt,
        ClaimsJson = "[]"
    };

    private static void UpdateEntity(UserEntity entity, CoreIdentUser user)
    {
        entity.UserName = user.UserName;
        entity.NormalizedUserName = user.NormalizedUserName;
        entity.PasswordHash = user.PasswordHash;
        entity.UpdatedAt = user.UpdatedAt;
    }

    private static string NormalizeUsername(string username) => username.Trim().ToUpperInvariant();

    private sealed record ClaimDto(string Type, string Value);
}
