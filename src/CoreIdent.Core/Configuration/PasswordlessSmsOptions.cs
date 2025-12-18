namespace CoreIdent.Core.Configuration;

/// <summary>
/// Options for passwordless SMS authentication.
/// </summary>
public sealed class PasswordlessSmsOptions
{
    /// <summary>
    /// Lifetime for issued one-time passcodes.
    /// </summary>
    public TimeSpan OtpLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum allowed verification attempts per recipient per hour.
    /// </summary>
    public int MaxAttemptsPerHour { get; set; } = 5;
}
