using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore.Models;

/// <summary>
/// EF Core entity representing a stored passkey (WebAuthn) credential.
/// </summary>
[PrimaryKey(nameof(CredentialId))]
public sealed class PasskeyCredentialEntity
{
    /// <summary>
    /// Gets or sets the user identifier that owns this credential.
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// Gets or sets the credential identifier.
    /// </summary>
    public required byte[] CredentialId { get; set; }

    /// <summary>
    /// Gets or sets the public key bytes.
    /// </summary>
    public required byte[] PublicKey { get; set; }

    /// <summary>
    /// Gets or sets the time the credential was created/registered.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the JSON-serialized list of authenticator transports.
    /// </summary>
    public string? TransportsJson { get; set; }

    /// <summary>
    /// Gets or sets the raw attestation object.
    /// </summary>
    public byte[]? AttestationObject { get; set; }

    /// <summary>
    /// Gets or sets the raw client data JSON.
    /// </summary>
    public byte[]? ClientDataJson { get; set; }

    /// <summary>
    /// Gets or sets the signature counter for replay protection.
    /// </summary>
    public uint SignatureCounter { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the credential is backed up.
    /// </summary>
    public bool IsBackedUp { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the credential is eligible for backup.
    /// </summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>
    /// Gets or sets an optional user-friendly name for the credential.
    /// </summary>
    public string? Name { get; set; }
}
