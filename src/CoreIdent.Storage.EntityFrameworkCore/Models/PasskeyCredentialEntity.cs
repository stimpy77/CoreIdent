using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Models;

[PrimaryKey(nameof(CredentialId))]
public sealed class PasskeyCredentialEntity
{
    public required string UserId { get; set; }

    public required byte[] CredentialId { get; set; }

    public required byte[] PublicKey { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public string? TransportsJson { get; set; }

    public byte[]? AttestationObject { get; set; }

    public byte[]? ClientDataJson { get; set; }

    public uint SignatureCounter { get; set; }

    public bool IsBackedUp { get; set; }

    public bool IsBackupEligible { get; set; }

    public string? Name { get; set; }
}
