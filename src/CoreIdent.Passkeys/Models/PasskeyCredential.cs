namespace CoreIdent.Passkeys.Models;

public sealed class PasskeyCredential
{
    public required string UserId { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public required byte[] CredentialId { get; init; }

    public required byte[] PublicKey { get; init; }

    public string[]? Transports { get; init; }

    public byte[]? AttestationObject { get; init; }

    public byte[]? ClientDataJson { get; init; }

    public uint SignatureCounter { get; set; }

    public bool IsBackedUp { get; set; }

    public bool IsBackupEligible { get; set; }

    public string? Name { get; set; }
}
