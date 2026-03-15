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

    /// <summary>
    /// Maximum failed verify attempts before the OTP is burned.
    /// Protects 6-digit OTPs from brute-force enumeration.
    /// </summary>
    public int MaxVerifyAttempts { get; set; } = 5;
}
