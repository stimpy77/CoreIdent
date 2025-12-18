using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="IClientStore"/>.
/// </summary>
public sealed class EfClientStore : IClientStore
{
    private readonly CoreIdentDbContext _context;
    private readonly IClientSecretHasher _secretHasher;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfClientStore"/> class.
    /// </summary>
    /// <param name="context">The EF Core database context.</param>
    /// <param name="secretHasher">The client secret hasher.</param>
    public EfClientStore(CoreIdentDbContext context, IClientSecretHasher secretHasher)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _secretHasher = secretHasher ?? throw new ArgumentNullException(nameof(secretHasher));
    }

    /// <inheritdoc />
    public async Task<CoreIdentClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        var entity = await _context.Clients
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientId == clientId, ct);

        return entity is null ? null : ToModel(entity);
    }

    /// <inheritdoc />
    public async Task<bool> ValidateClientSecretAsync(string clientId, string clientSecret, CancellationToken ct = default)
    {
        var entity = await _context.Clients
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientId == clientId, ct);

        if (entity is null)
        {
            return false;
        }

        if (entity.ClientType == nameof(ClientType.Public))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(entity.ClientSecretHash))
        {
            return false;
        }

        return _secretHasher.VerifySecret(clientSecret, entity.ClientSecretHash);
    }

    /// <inheritdoc />
    public async Task CreateAsync(CoreIdentClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(client.ClientId);

        var entity = ToEntity(client);
        _context.Clients.Add(entity);
        await _context.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task UpdateAsync(CoreIdentClient client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(client.ClientId);

        var entity = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == client.ClientId, ct)
            ?? throw new InvalidOperationException($"Client with ID '{client.ClientId}' does not exist.");

        UpdateEntity(entity, client);
        await _context.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string clientId, CancellationToken ct = default)
    {
        var entity = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId, ct);
        if (entity is not null)
        {
            _context.Clients.Remove(entity);
            await _context.SaveChangesAsync(ct);
        }
    }

    private static CoreIdentClient ToModel(ClientEntity entity) => new()
    {
        ClientId = entity.ClientId,
        ClientSecretHash = entity.ClientSecretHash,
        ClientName = entity.ClientName,
        ClientType = Enum.Parse<ClientType>(entity.ClientType),
        RedirectUris = JsonSerializer.Deserialize<List<string>>(entity.RedirectUrisJson) ?? [],
        PostLogoutRedirectUris = JsonSerializer.Deserialize<List<string>>(entity.PostLogoutRedirectUrisJson) ?? [],
        AllowedScopes = JsonSerializer.Deserialize<List<string>>(entity.AllowedScopesJson) ?? [],
        AllowedGrantTypes = JsonSerializer.Deserialize<List<string>>(entity.AllowedGrantTypesJson) ?? [],
        AccessTokenLifetimeSeconds = entity.AccessTokenLifetimeSeconds,
        RefreshTokenLifetimeSeconds = entity.RefreshTokenLifetimeSeconds,
        RequirePkce = entity.RequirePkce,
        RequireConsent = entity.RequireConsent,
        AllowOfflineAccess = entity.AllowOfflineAccess,
        Enabled = entity.Enabled,
        CreatedAt = entity.CreatedAt,
        UpdatedAt = entity.UpdatedAt
    };

    private static ClientEntity ToEntity(CoreIdentClient client) => new()
    {
        ClientId = client.ClientId,
        ClientSecretHash = client.ClientSecretHash,
        ClientName = client.ClientName,
        ClientType = client.ClientType.ToString(),
        RedirectUrisJson = JsonSerializer.Serialize(client.RedirectUris),
        PostLogoutRedirectUrisJson = JsonSerializer.Serialize(client.PostLogoutRedirectUris),
        AllowedScopesJson = JsonSerializer.Serialize(client.AllowedScopes),
        AllowedGrantTypesJson = JsonSerializer.Serialize(client.AllowedGrantTypes),
        AccessTokenLifetimeSeconds = client.AccessTokenLifetimeSeconds,
        RefreshTokenLifetimeSeconds = client.RefreshTokenLifetimeSeconds,
        RequirePkce = client.RequirePkce,
        RequireConsent = client.RequireConsent,
        AllowOfflineAccess = client.AllowOfflineAccess,
        Enabled = client.Enabled,
        CreatedAt = client.CreatedAt,
        UpdatedAt = client.UpdatedAt
    };

    private static void UpdateEntity(ClientEntity entity, CoreIdentClient client)
    {
        entity.ClientSecretHash = client.ClientSecretHash;
        entity.ClientName = client.ClientName;
        entity.ClientType = client.ClientType.ToString();
        entity.RedirectUrisJson = JsonSerializer.Serialize(client.RedirectUris);
        entity.PostLogoutRedirectUrisJson = JsonSerializer.Serialize(client.PostLogoutRedirectUris);
        entity.AllowedScopesJson = JsonSerializer.Serialize(client.AllowedScopes);
        entity.AllowedGrantTypesJson = JsonSerializer.Serialize(client.AllowedGrantTypes);
        entity.AccessTokenLifetimeSeconds = client.AccessTokenLifetimeSeconds;
        entity.RefreshTokenLifetimeSeconds = client.RefreshTokenLifetimeSeconds;
        entity.RequirePkce = client.RequirePkce;
        entity.RequireConsent = client.RequireConsent;
        entity.AllowOfflineAccess = client.AllowOfflineAccess;
        entity.Enabled = client.Enabled;
        entity.UpdatedAt = client.UpdatedAt;
    }
}
