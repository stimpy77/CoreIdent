namespace CoreIdent.Passkeys.Configuration;

/// <summary>
/// Options used to configure CoreIdent passkey (WebAuthn) behavior.
/// </summary>
public sealed class CoreIdentPasskeyOptions
{
    /// <summary>
    /// Gets or sets the client identifier used for passkey operations.
    /// </summary>
    public string ClientId { get; set; } = "passkey";

    /// <summary>
    /// Gets or sets the WebAuthn relying party identifier (RP ID). If not set, the host should determine the appropriate value.
    /// </summary>
    public string? RelyingPartyId { get; set; }

    /// <summary>
    /// Gets or sets the relying party display name.
    /// </summary>
    public string RelyingPartyName { get; set; } = "CoreIdent";

    /// <summary>
    /// Gets or sets the timeout applied to registration/authentication challenges.
    /// </summary>
    public TimeSpan ChallengeTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the challenge size in bytes.
    /// </summary>
    public int ChallengeSize { get; set; } = 32;
}
