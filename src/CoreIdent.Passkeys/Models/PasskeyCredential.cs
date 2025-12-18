namespace CoreIdent.Passkeys.Models;

/// <summary>
/// Represents a stored passkey (WebAuthn) credential associated with a CoreIdent user.
/// </summary>
public sealed class PasskeyCredential
{
    /// <summary>
    /// Gets the CoreIdent user identifier that owns this credential.
    /// </summary>
    public required string UserId { get; init; }

    /// <summary>
    /// Gets the time the credential was created/registered.
    /// </summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// Gets the raw credential identifier returned by the authenticator.
    /// </summary>
    public required byte[] CredentialId { get; init; }

    /// <summary>
    /// Gets the raw public key bytes used to verify assertions.
    /// </summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// Gets the authenticator transports for this credential, if provided.
    /// </summary>
    public string[]? Transports { get; init; }

    /// <summary>
    /// Gets the attestation object returned during registration, if stored.
    /// </summary>
    public byte[]? AttestationObject { get; init; }

    /// <summary>
    /// Gets the client data JSON returned during registration, if stored.
    /// </summary>
    public byte[]? ClientDataJson { get; init; }

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
