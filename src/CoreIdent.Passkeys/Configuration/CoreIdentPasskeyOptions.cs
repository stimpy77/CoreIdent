namespace CoreIdent.Passkeys.Configuration;

public sealed class CoreIdentPasskeyOptions
{
    public string ClientId { get; set; } = "passkey";

    public string? RelyingPartyId { get; set; }

    public string RelyingPartyName { get; set; } = "CoreIdent";

    public TimeSpan ChallengeTimeout { get; set; } = TimeSpan.FromMinutes(5);

    public int ChallengeSize { get; set; } = 32;
}
