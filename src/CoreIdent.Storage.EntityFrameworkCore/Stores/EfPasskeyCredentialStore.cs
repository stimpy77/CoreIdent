using System.Text.Json;
using CoreIdent.Passkeys.Models;
using CoreIdent.Passkeys.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation of <see cref="IPasskeyCredentialStore"/>.
/// </summary>
public sealed class EfPasskeyCredentialStore : IPasskeyCredentialStore
{
    private readonly CoreIdentDbContext _db;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfPasskeyCredentialStore"/> class.
    /// </summary>
    /// <param name="db">The EF Core database context.</param>
    public EfPasskeyCredentialStore(CoreIdentDbContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var entities = await _db.PasskeyCredentials
            .AsNoTracking()
            .Where(x => x.UserId == userId)
            .ToListAsync(ct);

        return entities.Select(MapToModel).ToList();
    }

    /// <inheritdoc />
    public async Task<PasskeyCredential?> GetByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var entity = await _db.PasskeyCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.CredentialId == credentialId, ct);

        return entity is null ? null : MapToModel(entity);
    }

    /// <inheritdoc />
    public async Task UpsertAsync(PasskeyCredential credential, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var existing = await _db.PasskeyCredentials
            .FirstOrDefaultAsync(x => x.CredentialId == credential.CredentialId, ct);

        if (existing is null)
        {
            _db.PasskeyCredentials.Add(MapToEntity(credential));
        }
        else
        {
            existing.UserId = credential.UserId;
            existing.PublicKey = credential.PublicKey;
            existing.CreatedAt = credential.CreatedAt;
            existing.TransportsJson = credential.Transports is null ? null : JsonSerializer.Serialize(credential.Transports);
            existing.AttestationObject = credential.AttestationObject;
            existing.ClientDataJson = credential.ClientDataJson;
            existing.SignatureCounter = credential.SignatureCounter;
            existing.IsBackedUp = credential.IsBackedUp;
            existing.IsBackupEligible = credential.IsBackupEligible;
            existing.Name = credential.Name;
        }

        await _db.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string userId, byte[] credentialId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(credentialId);

        var entity = await _db.PasskeyCredentials
            .FirstOrDefaultAsync(x => x.UserId == userId && x.CredentialId == credentialId, ct);

        if (entity is null)
        {
            return;
        }

        _db.PasskeyCredentials.Remove(entity);
        await _db.SaveChangesAsync(ct);
    }

    private static PasskeyCredential MapToModel(PasskeyCredentialEntity entity)
    {
        return new PasskeyCredential
        {
            UserId = entity.UserId,
            CreatedAt = entity.CreatedAt,
            CredentialId = entity.CredentialId,
            PublicKey = entity.PublicKey,
            Transports = string.IsNullOrWhiteSpace(entity.TransportsJson)
                ? null
                : JsonSerializer.Deserialize<string[]>(entity.TransportsJson),
            AttestationObject = entity.AttestationObject,
            ClientDataJson = entity.ClientDataJson,
            SignatureCounter = entity.SignatureCounter,
            IsBackedUp = entity.IsBackedUp,
            IsBackupEligible = entity.IsBackupEligible,
            Name = entity.Name,
        };
    }

    private static PasskeyCredentialEntity MapToEntity(PasskeyCredential model)
    {
        return new PasskeyCredentialEntity
        {
            UserId = model.UserId,
            CredentialId = model.CredentialId,
            PublicKey = model.PublicKey,
            CreatedAt = model.CreatedAt,
            TransportsJson = model.Transports is null ? null : JsonSerializer.Serialize(model.Transports),
            AttestationObject = model.AttestationObject,
            ClientDataJson = model.ClientDataJson,
            SignatureCounter = model.SignatureCounter,
            IsBackedUp = model.IsBackedUp,
            IsBackupEligible = model.IsBackupEligible,
            Name = model.Name,
        };
    }
}
