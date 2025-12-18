namespace CoreIdent.Core.Services;

/// <summary>
/// Well-known passwordless token type identifiers.
/// </summary>
public static class PasswordlessTokenTypes
{
    /// <summary>
    /// Email magic-link token type.
    /// </summary>
    public const string EmailMagicLink = "email_magic_link";

    /// <summary>
    /// SMS one-time passcode (OTP) token type.
    /// </summary>
    public const string SmsOtp = "sms_otp";
}
